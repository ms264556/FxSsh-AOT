using System;
using System.Linq;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class CipherInfo
    {
        public CipherInfo(SymmetricAlgorithm algorithm, int keySize, CipherModeEx mode)
        {
            ArgumentNullException.ThrowIfNull(algorithm);
            if (!algorithm.LegalKeySizes.Any(x =>
                x.MinSize <= keySize && keySize <= x.MaxSize
                && (x.SkipSize == 0 ? keySize == x.MinSize : keySize % x.SkipSize == 0)))
                throw new ArgumentOutOfRangeException(nameof(keySize), keySize, "Key size is not legal for the algorithm.");

            algorithm.KeySize = keySize;
            KeySize = algorithm.KeySize;
            BlockSize = algorithm.BlockSize;
            Cipher = (key, iv, isEncryption) => new EncryptionAlgorithm(algorithm, keySize, mode, key, iv, isEncryption);
        }

        public int KeySize { get; private set; }

        public int BlockSize { get; private set; }

        public Func<byte[], byte[], bool, EncryptionAlgorithm> Cipher { get; private set; }
    }
}
