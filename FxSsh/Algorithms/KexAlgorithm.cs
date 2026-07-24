using System;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public abstract class KexAlgorithm
    {
        protected HashAlgorithm _hashAlgorithm;

        public abstract byte[] CreateKeyExchange();

        public abstract byte[] DecryptKeyExchange(byte[] exchangeData);

        public byte[] ComputeHash(byte[] input)
        {
            ArgumentNullException.ThrowIfNull(input);

            return _hashAlgorithm.ComputeHash(input);
        }
    }
}
