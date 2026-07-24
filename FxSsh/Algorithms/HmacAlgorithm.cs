using System;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class HmacAlgorithm
    {
        private readonly KeyedHashAlgorithm _algorithm;

        public HmacAlgorithm(KeyedHashAlgorithm algorithm, int keySize, byte[] key)
        {
            ArgumentNullException.ThrowIfNull(algorithm);
            ArgumentNullException.ThrowIfNull(key);
            if (keySize != key.Length << 3)
                throw new ArgumentException("Key size must match the key length in bits.", nameof(keySize));

            _algorithm = algorithm;
            algorithm.Key = key;
        }

        public int DigestLength
        {
            get { return _algorithm.HashSize >> 3; }
        }

        public byte[] ComputeHash(byte[] input)
        {
            ArgumentNullException.ThrowIfNull(input);

            return _algorithm.ComputeHash(input);
        }
    }
}
