using System;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class HmacInfo
    {
        public HmacInfo(KeyedHashAlgorithm algorithm, int keySize, bool isEtm = false)
        {
            ArgumentNullException.ThrowIfNull(algorithm);

            KeySize = keySize;
            IsEtm = isEtm;
            Hmac = key => new HmacAlgorithm(algorithm, keySize, key);
        }

        public int KeySize { get; private set; }

        /// <summary>
        /// True for Encrypt-then-MAC algorithms (-etm@openssh.com, RFC 6668).
        /// When true, the MAC covers the ciphertext instead of the plaintext.
        /// </summary>
        public bool IsEtm { get; private set; }

        public Func<byte[], HmacAlgorithm> Hmac { get; private set; }
    }
}
