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
                // IV is materialised by key exchange — first 4 bytes fixed field,
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
            IsAead = false;
        }

        /// <summary>
        /// True for AES-GCM (RFC 5647). AEAD packets carry their auth tag
        /// inline and do NOT use a separate HMAC; Session.Send/ReceiveMessage
        /// branch on this to skip the HMAC computation and emit/parse the tag.
        /// </summary>
        public bool IsAead { get; }

        /// <summary>Block size in bytes used for padding alignment (16 for AES-GCM).</summary>
        public int BlockBytesSize
        {
            get { return _mode == CipherModeEx.GCM ? 16 : _algorithm.BlockSize >> 3; }
        }

        /// <summary>GCM auth tag length (16). Only valid when IsAead.</summary>
        public int TagBytes
        {
            get
            {
                if (_gcmTransform == null)
                    throw new InvalidOperationException("TagBytes is only defined for AEAD (GCM) algorithms.");
                return _gcmTransform.TagBytes;
            }
        }

        /// <summary>CTR/CBC streaming encrypt/decrypt (not valid for GCM).</summary>
        public byte[] Transform(byte[] input)
        {
            var output = new byte[input.Length];
            Transform(input, output);
            return output;
        }

        /// <summary>CTR/CBC streaming encrypt/decrypt (not valid for GCM).</summary>
        public void Transform(byte[] input, byte[] output)
        {
            if (_transform == null)
                throw new InvalidOperationException("Transform is only valid for CBC/CTR; use EncryptAead/DecryptAead for GCM.");
            _transform.TransformBlock(input, 0, input.Length, output, 0);
        }

        /// <summary>
        /// AEAD encrypt one SSH packet. <paramref name="aad"/> is the 4-byte
        /// plaintext packet_length (RFC 5647 section 7.3 — authenticated but not
        /// encrypted); <paramref name="plaintext"/> is padding_length ||
        /// payload || padding. Returns ciphertext || tag, ready to follow the
        /// plaintext packet_length in the on-wire layout
        /// [packet_length(4)][ciphertext][tag]. Caller must advance the
        /// outbound packet sequence separately (Session does so after the write).
        /// </summary>
        public byte[] EncryptAead(byte[] aad, byte[] plaintext)
        {
            if (_gcmTransform == null)
                throw new InvalidOperationException("EncryptAead is only valid for GCM.");
            return _gcmTransform.Encrypt(aad, plaintext);
        }

        /// <summary>
        /// AEAD decrypt one SSH packet: <paramref name="aad"/> is the 4-byte
        /// plaintext packet_length (RFC 5647 §7.3); <paramref name="ciphertextWithTag"/>
        /// is ciphertext || tag, output is plaintext. Throws CryptographicException
        /// on tag mismatch — Session maps that to DisconnectReason.MacError,
        /// matching the HMAC path.
        /// </summary>
        public byte[] DecryptAead(byte[] aad, byte[] ciphertextWithTag)
        {
            if (_gcmTransform == null)
                throw new InvalidOperationException("DecryptAead is only valid for GCM.");
            return _gcmTransform.Decrypt(aad, ciphertextWithTag);
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
