using System;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public abstract class KexAlgorithm
    {
        protected HashAlgorithm _hashAlgorithm;

        public abstract byte[] CreateKeyExchange();

        public abstract byte[] DecryptKeyExchange(byte[] exchangeData);

        /// <summary>
        /// True when the shared secret K enters the exchange hash and the key
        /// derivation (RFC 4253 section 7.2) as an SSH string (hybrid PQ/T
        /// methods, e.g. mlkem768x25519-sha256), instead of the mpint used by
        /// classical ECDH/DH methods.
        /// </summary>
        public virtual bool SharedSecretIsString => false;

        public byte[] ComputeHash(byte[] input)
        {
            ArgumentNullException.ThrowIfNull(input);

            return _hashAlgorithm.ComputeHash(input);
        }
    }
}
