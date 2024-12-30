using System;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;
using System.Text;

namespace FxSsh.Algorithms
{
    public class RsaKey : PublicKeyAlgorithm
    {
        private readonly RSA _algorithm = RSA.Create();
        private readonly string _name;
        private readonly HashAlgorithmName _sha;

        public RsaKey(int sha2Bitlen, string key)
            : base(key)
        {
            Contract.Requires(sha2Bitlen == 256 || sha2Bitlen == 512);

            switch (sha2Bitlen)
            {
                case 256:
                    _name = "rsa-sha2-256";
                    _sha = HashAlgorithmName.SHA256;
                    break;
                case 512:
                    _name = "rsa-sha2-512";
                    _sha = HashAlgorithmName.SHA512;
                    break;
                default:
                    throw new ArgumentException("sha2Bitlen must equal 256, or 512", nameof(sha2Bitlen));
            }
        }

        public override string Name
        {
            get { return _name; }
        }

        public override string PublicKeyName
        {
            get { return "ssh-rsa"; }
        }

        public override void ImportKey(string key)
        {
            _algorithm.ImportFromPem(key);
        }

        public override string ExportKey()
        {
            return _algorithm.ExportPkcs8PrivateKeyPem();
        }

        public override void LoadKeyAndCertificatesData(byte[] data)
        {
            using (var worker = new SshDataWorker(data))
            {
                if (worker.ReadString(Encoding.ASCII) != PublicKeyName)
                    throw new CryptographicException("Key and certificates were not created with this algorithm.");

                var args = new RSAParameters
                {
                    Exponent = worker.ReadMpint(),
                    Modulus = worker.ReadMpint(),
                };

                _algorithm.ImportParameters(args);
            }
        }

        public override byte[] CreateKeyAndCertificatesData()
        {
            using (var worker = new SshDataWorker())
            {
                var args = _algorithm.ExportParameters(false);

                worker.Write(PublicKeyName, Encoding.ASCII);
                worker.WriteMpint(args.Exponent);
                worker.WriteMpint(args.Modulus);

                return worker.ToByteArray();
            }
        }

        public override bool VerifyData(byte[] data, byte[] signature)
        {
            return _algorithm.VerifyData(data, signature, _sha, RSASignaturePadding.Pkcs1);
        }

        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            return _algorithm.VerifyHash(hash, signature, _sha, RSASignaturePadding.Pkcs1);
        }

        public override byte[] SignData(byte[] data)
        {
            return _algorithm.SignData(data, _sha, RSASignaturePadding.Pkcs1);
        }

        public override byte[] SignHash(byte[] hash)
        {
            return _algorithm.SignHash(hash, _sha, RSASignaturePadding.Pkcs1);
        }
    }
}
