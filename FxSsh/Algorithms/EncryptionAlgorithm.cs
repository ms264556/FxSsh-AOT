using System;
using System.ComponentModel;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class EncryptionAlgorithm
    {
        private readonly SymmetricAlgorithm _algorithm;
        private readonly CipherModeEx _mode;
        private readonly ICryptoTransform _transform;

        // GCM (AEAD) branch: replaces the streaming _transform with a single
        // per-packet invoker. Null when _mode is CBC/CTR.
        private readonly GcmModeCryptoTransform _gcmTransform;

        // Plugin AEAD (chacha20-poly1305@openssh.com and friends) branch: a
        // per-direction transform supplied from outside the library. Null for
        // the built-in streaming/AES-GCM algorithms.
        private readonly IAeadTransform _aeadTransform;

        // Plugin AEAD block size in bytes (8 for chacha20-poly1305@openssh.com);
        // only meaningful when _aeadTransform != null.
        private readonly int _blockBytesSize;

        public EncryptionAlgorithm(SymmetricAlgorithm algorithm, int keySize, CipherModeEx mode, byte[] key, byte[] iv, bool isEncryption)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(iv);
            if (keySize != key.Length << 3)
                throw new ArgumentException("Key size must match the key length in bits.", nameof(keySize));

            _mode = mode;

            if (mode == CipherModeEx.GCM)
            {
                // RFC 5647 section 7.1 + OpenSSL SET_IV_FIXED(arg=-1): the full 12-byte
                // IV is materialised by key exchange - first 4 bytes fixed field,
                // last 8 bytes seed the invocation counter (NOT zero). AesGcm owns
                // the key; _algorithm is left null and the SymmetricAlgorithm
                // parameter is unused (CipherInfo's GCM ctor passes null), so we
                // do NOT ThrowIfNull(algorithm) here.
                if (iv.Length != 12)
                    throw new ArgumentException("AES-GCM IV must be 12 bytes (fixed(4) || invocation_counter(8), RFC 5647 section 7.1).", nameof(iv));

                _gcmTransform = new GcmModeCryptoTransform(key, iv);
                _algorithm = null;
                _transform = null;
                IsAead = true;
                return;
            }

            // CBC/CTR path: a SymmetricAlgorithm instance is mandatory.
            ArgumentNullException.ThrowIfNull(algorithm);

            algorithm.KeySize = keySize;
            algorithm.Key = key;
            algorithm.IV = iv;
            algorithm.Padding = PaddingMode.None;

            _algorithm = algorithm;
            _transform = CreateTransform(isEncryption);
            _gcmTransform = null;
            _aeadTransform = null;
            IsAead = false;
        }

        /// <summary>
        /// Plugin AEAD constructor for ciphers supplied from outside the
        /// library (e.g. chacha20-poly1305@openssh.com, whose transform lives
        /// in FxSsh.Tests). <paramref name="aeadTransform"/> is a per-direction
        /// transform built from the KEX-derived key; <paramref name="blockSizeBytes"/>
        /// drives packet_length / padding alignment (8 for chacha20-poly1305@openssh.com).
        /// </summary>
        public EncryptionAlgorithm(IAeadTransform aeadTransform, int blockSizeBytes)
        {
            ArgumentNullException.ThrowIfNull(aeadTransform);
            if (blockSizeBytes <= 0)
                throw new ArgumentOutOfRangeException(nameof(blockSizeBytes));

            _aeadTransform = aeadTransform;
            _blockBytesSize = blockSizeBytes;
            _algorithm = null;
            _transform = null;
            _gcmTransform = null;
            _mode = CipherModeEx.CTR; // unused; BlockBytesSize is plugin-gaured
            IsAead = true;
        }

        /// <summary>
        /// True for AES-GCM (RFC 5647). AEAD packets carry their auth tag
        /// inline and do NOT use a separate HMAC; Session.Send/ReceiveMessage
        /// branch on this to skip the HMAC computation and emit/parse the tag.
        /// </summary>
        public bool IsAead { get; }

        /// <summary>Block size in bytes used for padding alignment (16 for AES-GCM, 8 for chacha20-poly1305).</summary>
        public int BlockBytesSize
        {
            get
            {
                if (_aeadTransform != null) return _blockBytesSize;
                return _mode == CipherModeEx.GCM ? 16 : _algorithm.BlockSize >> 3;
            }
        }

        /// <summary>Auth tag length in bytes (16 for AES-GCM and chacha20-poly1305). Only valid when IsAead.</summary>
        public int TagBytes
        {
            get
            {
                if (_aeadTransform != null) return _aeadTransform.TagBytes;
                if (_gcmTransform == null)
                    throw new InvalidOperationException("TagBytes is only defined for AEAD algorithms.");
                return _gcmTransform.TagBytes;
            }
        }

        /// <summary>CTR/CBC streaming encrypt/decrypt (not valid for GCM).</summary>
        public byte[] Transform(byte[] input)
        {
            var output = new byte[input.Length];
            Transform(input, input.Length, output);
            return output;
        }

        /// <summary>CTR/CBC streaming encrypt/decrypt (not valid for GCM).</summary>
        public void Transform(byte[] input, byte[] output)
        {
            Transform(input, input.Length, output);
        }

        /// <summary>
        /// CTR/CBC streaming encrypt/decrypt over exactly
        /// <paramref name="inputLength"/> bytes (not valid for GCM).
        ///
        /// <paramref name="inputLength"/> may be smaller than
        /// <paramref name="input"/>.Length - callers that hold a pooled buffer
        /// larger than the actual packet MUST pass the exact byte count:
        /// ICryptoTransform.TransformBlock processes the entire supplied
        /// count, and the CTR implementation advances its keystream counter
        /// by exactly that many bytes. Feeding it a rented buffer's full
        /// length would over-advance the counter and corrupt every subsequent
        /// packet's decryption.
        /// </summary>
        public void Transform(byte[] input, int inputLength, byte[] output)
        {
            Transform(input, 0, inputLength, output, 0);
        }

        /// <summary>
        /// CTR/CBC streaming encrypt/decrypt over exactly
        /// <paramref name="inputLength"/> bytes starting at
        /// <paramref name="inputOffset"/>, writing to <paramref name="outputOffset"/>
        /// (not valid for GCM). Supports in-place use (input == output), which
        /// the ETM send path exploits to encrypt the packet body at [4..]
        /// without a scratch array.
        /// </summary>
        public void Transform(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            if (_transform == null)
                throw new InvalidOperationException("Transform is only valid for CBC/CTR; use EncryptAead/DecryptAead for GCM.");
            if (inputLength < 0 || inputOffset < 0 || inputLength > input.Length - inputOffset)
                throw new ArgumentOutOfRangeException(nameof(inputLength));
            if (outputOffset < 0 || inputLength > output.Length - outputOffset)
                throw new ArgumentOutOfRangeException(nameof(outputOffset));
            _transform.TransformBlock(input, inputOffset, inputLength, output, outputOffset);
        }

        /// <summary>
        /// AEAD encrypt one SSH packet straight into <paramref name="destination"/>:
        /// <paramref name="aad"/> is the 4-byte plaintext packet_length (RFC 5647
        /// section 7.3 - authenticated but not encrypted); <paramref name="plaintext"/>
        /// is padding_length || payload || padding. Writes ciphertext || tag,
        /// ready to follow the plaintext packet_length in the on-wire layout
        /// [packet_length(4)][ciphertext][tag]. Caller must advance the
        /// outbound packet sequence separately (Session does so after the write).
        ///
        /// <paramref name="destination"/> must be at least
        /// <paramref name="plaintext"/>.Length + TagBytes long. No intermediate
        /// allocation on the hot path.
        /// </summary>
        public void EncryptAead(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext, Span<byte> destination)
        {
            if (_gcmTransform == null)
                throw new InvalidOperationException("EncryptAead is only valid for GCM.");
            _gcmTransform.Encrypt(aad, plaintext, destination);
        }

        /// <summary>
        /// AEAD decrypt one SSH packet straight into <paramref name="plaintextDestination"/>:
        /// <paramref name="aad"/> is the 4-byte plaintext packet_length (RFC 5647
        /// section 7.3 - authenticated but not encrypted);
        /// <paramref name="ciphertextWithTag"/> is ciphertext || tag.
        /// Throws CryptographicException on tag mismatch - Session maps that to
        /// DisconnectReason.MacError, matching the HMAC path.
        ///
        /// <paramref name="plaintextDestination"/> must be at least
        /// <paramref name="ciphertextWithTag"/>.Length - TagBytes long.
        /// No intermediate allocation on the hot path.
        /// </summary>
        public void DecryptAead(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintextDestination)
        {
            if (_gcmTransform == null)
                throw new InvalidOperationException("DecryptAead is only valid for GCM.");
            _gcmTransform.Decrypt(aad, ciphertextWithTag, plaintextDestination);
        }

        /// <summary>True when this cipher is a plugin IAeadTransform (e.g. chacha20-poly1305@openssh.com) rather than built-in AES-GCM.</summary>
        public bool IsTransformCipher => _aeadTransform != null;

        /// <summary>
        /// Plugin AEAD: turn the 4 on-wire packet_length bytes into the
        /// plaintext length (identity for AES-GCM, K2-keystream decrypt for
        /// chacha20-poly1305@openssh.com). Only valid when
        /// <see cref="IsTransformCipher"/> is true.
        /// </summary>
        public int DecryptPacketLength(uint sequenceNumber, ReadOnlySpan<byte> encryptedLength)
        {
            if (_aeadTransform == null)
                throw new InvalidOperationException("DecryptPacketLength is only valid for plugin AEAD ciphers.");
            return _aeadTransform.DecryptPacketLength(sequenceNumber, encryptedLength);
        }

        /// <summary>
        /// Plugin AEAD: encrypt one SSH packet straight into
        /// <paramref name="destination"/>. <paramref name="frame"/> is
        /// [packet_length(4)][padding_length||payload||padding]; output is
        /// [length_field(4)][ciphertext][tag].
        /// </summary>
        public void EncryptAeadPacket(uint sequenceNumber, ReadOnlySpan<byte> frame, Span<byte> destination)
        {
            if (_aeadTransform == null)
                throw new InvalidOperationException("EncryptAeadPacket is only valid for plugin AEAD ciphers.");
            _aeadTransform.Encrypt(sequenceNumber, frame, destination);
        }

        /// <summary>
        /// Plugin AEAD: authenticate and decrypt one SSH packet straight into
        /// <paramref name="plaintextDestination"/>. <paramref name="lengthField"/>
        /// is the 4 on-wire length bytes and <paramref name="ciphertextWithTag"/>
        /// is ciphertext || tag.
        /// </summary>
        public void DecryptAeadPacket(uint sequenceNumber, ReadOnlySpan<byte> lengthField, ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintextDestination)
        {
            if (_aeadTransform == null)
                throw new InvalidOperationException("DecryptAeadPacket is only valid for plugin AEAD ciphers.");
            _aeadTransform.Decrypt(sequenceNumber, lengthField, ciphertextWithTag, plaintextDestination);
        }

        private ICryptoTransform CreateTransform(bool isEncryption)
        {
            switch (_mode)
            {
                case CipherModeEx.CBC:
                    _algorithm.Mode = CipherMode.CBC;
                    return isEncryption
                        ? _algorithm.CreateEncryptor()
                        : _algorithm.CreateDecryptor();
                case CipherModeEx.CTR:
                    return new CtrModeCryptoTransform(_algorithm);
                case CipherModeEx.GCM:
                    // GCM never reaches here: handled in the ctor's AEAD branch.
                    throw new InvalidOperationException("GCM has no streaming ICryptoTransform; use EncryptAead/DecryptAead.");
                default:
                    throw new InvalidEnumArgumentException(string.Format("Invalid mode: {0}", _mode));
            }
        }
    }
}
