using System.Diagnostics.Contracts;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class EcdhKex : KexAlgorithm
    {
        private readonly ECDiffieHellman _ecdh;

        public EcdhKex(string curveName)
        {
            Contract.Requires(curveName == "nistp256" || curveName == "nistp384" || curveName == "nistp521");

            if (curveName == "nistp256")
            {
                _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                _hashAlgorithm = SHA256.Create();
            }
            else if (curveName == "nistp384")
            {
                _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
                _hashAlgorithm = SHA384.Create();
            }
            else if (curveName == "nistp521")
            {
                _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521);
                _hashAlgorithm = SHA512.Create();
            }
        }

        public override byte[] CreateKeyExchange()
        {
            var q = _ecdh.PublicKey.ExportParameters().Q;
            using (var worker = new SshDataWorker())
            {
                worker.Write(0x04);
                worker.Write(q.X);
                worker.Write(q.Y);

                return worker.ToByteArray();
            }
        }

        public override byte[] DecryptKeyExchange(byte[] exchangeData)
        {
            Contract.Requires(exchangeData != null);

            var args = new ECParameters();
            args.Curve = _ecdh.PublicKey.ExportParameters().Curve;
            using (var worker = new SshDataWorker(exchangeData))
            {
                if (worker.ReadByte() != 0x04)
                    throw new InvalidDataException();
                var qlength = (exchangeData.Length - 1) / 2;
                var x = worker.ReadBinary(qlength);
                var y = worker.ReadBinary(qlength);
                args.Q = new ECPoint { X = x, Y = y };
            }

            var clientPublicKey = ECDiffieHellman.Create(args).PublicKey;
            var agreement = _ecdh.DeriveRawSecretAgreement(clientPublicKey);
            var sharedSecret = new BigInteger(agreement, isUnsigned: true, isBigEndian: true)
                .ToByteArray(isUnsigned: false, isBigEndian: true);

            return sharedSecret;
        }
    }
}
