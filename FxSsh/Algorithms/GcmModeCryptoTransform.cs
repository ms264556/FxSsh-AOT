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
    /// Nonce layout per RFC 5647 section 7.1 and the OpenSSH/OpenSSL implementation
    /// (cipher.c + EVP_CTRL_GCM_SET_IV_FIXED with arg=-1): the full 12-byte
    /// IV is materialised by key exchange. The first 4 bytes are the fixed
    /// field; the last 8 bytes seed the invocation counter and are NOT reset
    /// to zero — OpenSSL's EVP_CTRL_GCM_IV_GEN "generate precounter block
    /// from the IV, then increment the last eight bytes by 1" means the very
    /// first packet uses the IV's last 8 bytes verbatim as the counter, and
    /// each subsequent packet adds 1. We mirror that exactly: counter starts
    /// at the IV's last 8 bytes and is advanced once per packet, big-endian.
    /// </summary>
    public sealed class GcmModeCryptoTransform
    {
        private readonly AesGcm _gcm;
        private readonly byte[] _fixedIV;   // first 4 bytes of every nonce
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
            _fixedIV = new byte[4];
            Buffer.BlockCopy(iv, 0, _fixedIV, 0, 4);
            // Counter is seeded from the IV's last 8 bytes — NOT zero. OpenSSL's
            // SET_IV_FIXED(arg=-1) copies the entire 12-byte IV, and IV_GEN uses
            // the current IV for the current packet before incrementing, so the
            // first packet's counter == the IV's last 8 bytes verbatim.
            _counter = new byte[8];
            Buffer.BlockCopy(iv, 4, _counter, 0, 8);
        }

        /// <summary>Tag length in bytes (always 16 for SSH GCM).</summary>
        public int TagBytes => _tagBytes;

        /// <summary>
        /// Encrypt one SSH packet. <paramref name="aad"/> is the 4-byte
        /// plaintext packet_length (RFC 5647 section 7.3 — authenticated but not
        /// encrypted); <paramref name="plaintext"/> is padding_length ||
        /// payload || padding. Returns ciphertext || tag, ready to follow the
        /// plaintext packet_length on the wire as
        /// [packet_length(4)][ciphertext][tag(16)].
        /// </summary>
        public byte[] Encrypt(byte[] aad, byte[] plaintext)
        {
            ArgumentNullException.ThrowIfNull(aad);
            ArgumentNullException.ThrowIfNull(plaintext);

            var nonce = BuildNonce();
            var ciphertext = new byte[plaintext.Length + _tagBytes];
            _gcm.Encrypt(nonce,
                plaintext,
                ciphertext.AsSpan(0, plaintext.Length),
                ciphertext.AsSpan(plaintext.Length, _tagBytes),
                aad);
            AdvanceCounter();
            return ciphertext;
        }

        /// <summary>
        /// Decrypt one SSH packet: <paramref name="aad"/> is the 4-byte
        /// plaintext packet_length (RFC 5647 section 7.3 — authenticated but not
        /// encrypted); <paramref name="ciphertextWithTag"/> is ciphertext || tag.
        /// Throws CryptographicException on tag mismatch — which Session maps to
        /// the same DisconnectReason.MacError used for HMAC verification failure,
        /// matching RFC 4253 section 6.4 guidance.
        /// </summary>
        public byte[] Decrypt(byte[] aad, byte[] ciphertextWithTag)
        {
            ArgumentNullException.ThrowIfNull(aad);
            ArgumentNullException.ThrowIfNull(ciphertextWithTag);

            if (ciphertextWithTag.Length < _tagBytes)
                throw new ArgumentException("GCM ciphertext shorter than tag.", nameof(ciphertextWithTag));

            var nonce = BuildNonce();
            var ciphertextLength = ciphertextWithTag.Length - _tagBytes;
            var plaintext = new byte[ciphertextLength];
            _gcm.Decrypt(nonce,
                ciphertextWithTag.AsSpan(0, ciphertextLength),
                ciphertextWithTag.AsSpan(ciphertextLength, _tagBytes),
                plaintext,
                aad);
            AdvanceCounter();
            return plaintext;
        }

        private byte[] BuildNonce()
        {
            var nonce = new byte[12];
            Buffer.BlockCopy(_fixedIV, 0, nonce, 0, 4);
            Buffer.BlockCopy(_counter, 0, nonce, 4, 8);
            return nonce;
        }

        private void AdvanceCounter()
        {
            // Big-endian increment of the 8-byte invocation counter. Once it
            // would wrap (2^64 packets — astronomically beyond any session)
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
