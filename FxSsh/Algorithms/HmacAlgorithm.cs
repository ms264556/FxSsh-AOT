using System;
using System.Buffers.Binary;
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

        public byte[] ComputeHash(byte[] a, byte[] b, uint sequence)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);

            // Hash (seq || a || b) incrementally so the caller never has to
            // materialize a combined ciphertext buffer for the MAC.
            Span<byte> seq = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(seq, sequence);
            _algorithm.TransformBlock(seq.ToArray(), 0, 4, null, 0);
            _algorithm.TransformBlock(a, 0, a.Length, null, 0);
            _algorithm.TransformBlock(b, 0, b.Length, null, 0);
            _algorithm.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            var hash = _algorithm.Hash;
            _algorithm.Initialize();
            return hash;
        }
    }
}
