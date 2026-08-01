using System;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// AES-GCM AEAD transform for the SSH aes256-gcm@openssh.com /
    /// aes128-gcm@openssh.com algorithms (RFC 5647 section 7).
    ///
    /// Unlike CTR/CBC, GCM cannot be modeled as an ICryptoTransform that
    /// processes bytes incrementally: each SSH packet is one atomic AEAD
    /// invocation with its own 12-byte nonce and a 16-byte auth tag. This
    /// class therefore does NOT pretend to be a streaming transform; it
    /// is consumed by Session.Send/ReceiveMessage through the dedicated
    /// AEAD entry points (EncryptAead / DecryptAead) on EncryptionAlgorithm,
    /// which in turn call Encrypt / Decrypt here.
    ///
    /// Hot-path allocation profile: zero. The 12-byte nonce is a reused
    /// instance field (only the 8-byte counter half is refreshed per
    /// packet), and Encrypt/Decrypt write straight into caller-supplied
    /// destination spans -- no intermediate nonce/ciphertext/plaintext
    /// arrays are allocated per packet. The underlying AesGcm call is
    /// already Span-based (OpenSSL/AES-NI), so the managed layer adds no
    /// allocations on top of the native cipher.
    ///
    /// Nonce layout per RFC 5647 section 7.1 and the OpenSSH/OpenSSL implementation
    /// (cipher.c + EVP_CTRL_GCM_SET_IV_FIXED with arg=-1): the full 12-byte
    /// IV is materialised by key exchange. The first 4 bytes are the fixed
    /// field; the last 8 bytes seed the invocation counter and are NOT reset
    /// to zero -- OpenSSL's EVP_CTRL_GCM_IV_GEN "generate precounter block
    /// from the IV, then increment the last eight bytes by 1" means the very
    /// first packet uses the IV's last 8 bytes verbatim as the counter, and
    /// each subsequent packet adds 1. We mirror that exactly: counter starts
    /// at the IV's last 8 bytes and is advanced once per packet, big-endian.
    /// </summary>
    public sealed class GcmModeCryptoTransform
    {
        private readonly AesGcm _gcm;
        // Reused 12-byte nonce: [0..4] is the fixed field (set once from the
        // IV at construction), [4..12] is refreshed from _counter per packet.
        private readonly byte[] _nonce = new byte[12];
        private readonly byte[] _counter;   // 8-byte big-endian invocation counter
        private readonly int _tagBytes = 16;

        public GcmModeCryptoTransform(byte[] key, byte[] iv)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(iv);

            if (key.Length != 16 && key.Length != 32)
                throw new ArgumentException("AES-GCM key must be 128 or 256 bits.", nameof(key));
            if (iv.Length != 12)
                throw new ArgumentException("AES-GCM IV must be 12 bytes (fixed(4) || invocation_counter(8), RFC 5647 section 7.1).", nameof(iv));

            _gcm = new AesGcm(key, _tagBytes);
            Buffer.BlockCopy(iv, 0, _nonce, 0, 4);
            // Counter is seeded from the IV's last 8 bytes -- NOT zero. OpenSSL's
            // SET_IV_FIXED(arg=-1) copies the entire 12-byte IV, and IV_GEN uses
            // the current IV for the current packet before incrementing, so the
            // first packet's counter == the IV's last 8 bytes verbatim.
            _counter = new byte[8];
            Buffer.BlockCopy(iv, 4, _counter, 0, 8);
        }

        /// <summary>Tag length in bytes (always 16 for SSH GCM).</summary>
        public int TagBytes => _tagBytes;

        /// <summary>
        /// Encrypt one SSH packet straight into <paramref name="destination"/>:
        /// <paramref name="aad"/> is the 4-byte plaintext packet_length
        /// (RFC 5647 section 7.3 - authenticated but not encrypted);
        /// <paramref name="plaintext"/> is padding_length || payload || padding.
        /// Writes ciphertext || tag, ready to follow the plaintext packet_length
        /// on the wire as [packet_length(4)][ciphertext][tag(16)].
        ///
        /// <paramref name="destination"/> must be at least
        /// <paramref name="plaintext"/>.Length + <see cref="TagBytes"/> long.
        /// No allocation on the hot path - the nonce is a reused instance
        /// buffer and the output lands directly in the caller's span.
        /// </summary>
        public void Encrypt(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext, Span<byte> destination)
        {
            if (destination.Length < plaintext.Length + _tagBytes)
                throw new ArgumentException("Destination too short for GCM ciphertext and tag.", nameof(destination));

            RefreshNonce();
            _gcm.Encrypt(_nonce,
                plaintext,
                destination[..plaintext.Length],
                destination[plaintext.Length..],
                aad);
            AdvanceCounter();
        }

        /// <summary>
        /// Decrypt one SSH packet straight into <paramref name="plaintextDestination"/>:
        /// <paramref name="aad"/> is the 4-byte plaintext packet_length
        /// (RFC 5647 section 7.3 - authenticated but not encrypted);
        /// <paramref name="ciphertextWithTag"/> is ciphertext || tag.
        /// Throws CryptographicException on tag mismatch - which Session maps to
        /// the same DisconnectReason.MacError used for HMAC verification failure,
        /// matching RFC 4253 section 6.4 guidance.
        ///
        /// <paramref name="plaintextDestination"/> must be at least
        /// <paramref name="ciphertextWithTag"/>.Length - <see cref="TagBytes"/>
        /// long. No allocation on the hot path.
        /// </summary>
        public void Decrypt(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintextDestination)
        {
            if (ciphertextWithTag.Length < _tagBytes)
                throw new ArgumentException("GCM ciphertext shorter than tag.", nameof(ciphertextWithTag));
            var plaintextLength = ciphertextWithTag.Length - _tagBytes;
            if (plaintextDestination.Length < plaintextLength)
                throw new ArgumentException("Destination too short for GCM plaintext.", nameof(plaintextDestination));

            RefreshNonce();
            _gcm.Decrypt(_nonce,
                ciphertextWithTag[..plaintextLength],
                ciphertextWithTag[plaintextLength..],
                plaintextDestination[..plaintextLength],
                aad);
            AdvanceCounter();
        }

        // Copy the current counter into the reused nonce buffer. Zero
        // allocation - the 12-byte nonce array is a single instance field.
        private void RefreshNonce()
        {
            _counter.CopyTo(_nonce.AsSpan(4));
        }

        private void AdvanceCounter()
        {
            // Big-endian increment of the 8-byte invocation counter. Once it
            // would wrap (2^64 packets -- astronomically beyond any session)
            // we throw rather than silently reuse a nonce, which would be a
            // catastrophic GCM failure.
            for (var i = _counter.Length - 1; i >= 0; i--)
            {
                if (++_counter[i] != 0)
                    return;
            }
            throw new InvalidOperationException("AES-GCM invocation counter exhausted (2^64 packets); re-key required.");
        }
    }
}
