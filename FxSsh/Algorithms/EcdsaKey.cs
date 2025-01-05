using System;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace FxSsh.Algorithms
{
    public class EcdsaKey : PublicKeyAlgorithm
    {
        private readonly ECDsa _algorithm = ECDsa.Create();
        private readonly HashAlgorithmName _sha;
        private readonly string _curveName;

        public EcdsaKey(string curveName, string key)
            : base(key)
        {
            Contract.Requires(curveName == "nistp256" || curveName == "nistp384" || curveName == "nistp521");

            _curveName = curveName;
            var noKey = string.IsNullOrEmpty(key);
            if (curveName == "nistp256")
            {
                if (noKey) _algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                _sha = HashAlgorithmName.SHA256;
            }
            else if (curveName == "nistp384")
            {
                if (noKey) _algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP384);
                _sha = HashAlgorithmName.SHA384;
            }
            else if (curveName == "nistp521")
            {
                if (noKey) _algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP521);
                _sha = HashAlgorithmName.SHA512;
            }
        }

        public override string Name
        {
            get { return $"ecdsa-sha2-{_curveName}"; }
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
                if (worker.ReadString(Encoding.ASCII) != this.Name
                    || worker.ReadString(Encoding.ASCII) != _curveName)
                    throw new CryptographicException("Key and certificates were not created with this algorithm.");

                var bytesQ = worker.ReadBinary();
                using (var worker2 = new SshDataWorker(bytesQ))
                {
                    if (worker2.ReadByte() != 0x04)
                        throw new CryptographicException("Curve point compression is not supported.");
                    var fieldSize = bytesQ.Length / 2;
                    var args = _algorithm.ExportParameters(false);
                    args.Q.X = worker2.ReadBinary(fieldSize);
                    args.Q.Y = worker2.ReadBinary(fieldSize);

                    _algorithm.ImportParameters(args);
                }
            }
        }

        public override byte[] CreateKeyAndCertificatesData()
        {
            using (var worker = new SshDataWorker())
            {
                var args = _algorithm.ExportParameters(false);

                worker.Write(this.Name, Encoding.ASCII);
                worker.Write(_curveName, Encoding.ASCII);
                using (var worker2 = new SshDataWorker())
                {
                    worker2.Write(0x04);
                    worker2.Write(args.Q.X);
                    worker2.Write(args.Q.Y);

                    worker.WriteBinary(worker2.ToByteArray());
                }

                return worker.ToByteArray();
            }
        }

        public override bool VerifyData(byte[] data, byte[] signature)
        {
            var sig = SignatureBlobToP1363(signature);
            return _algorithm.VerifyData(data, sig, _sha, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            var sig = SignatureBlobToP1363(signature);
            return _algorithm.VerifyHash(hash, sig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        private byte[] SignatureBlobToP1363(byte[] signatureBlob)
        {
            using (var worker = new SshDataWorker(signatureBlob))
            {
                var r = worker.ReadMpint();
                var s = worker.ReadMpint();
                var fieldSize = (_algorithm.KeySize + 7) >> 3;
                // equal to (int)Math.Ceiling((double)_algorithm.KeySize / 8);
                //_algorithm.KeySize == 256 ? 32 :
                //_algorithm.KeySize == 384 ? 48 :
                //_algorithm.KeySize == 521 ? 66 :
                //throw new InvalidDataException();
                var bytes = new byte[fieldSize * 2];
                Array.Copy(r, 0, bytes, fieldSize - r.Length, r.Length);
                Array.Copy(s, 0, bytes, fieldSize + fieldSize - s.Length, s.Length);
                return bytes;
            }
        }

        public override byte[] SignData(byte[] data)
        {
            var sig = _algorithm.SignData(data, _sha, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return P1363ToSignatureBlob(sig);
        }

        public override byte[] SignHash(byte[] hash)
        {
            var sig = _algorithm.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return P1363ToSignatureBlob(sig);
        }

        private byte[] P1363ToSignatureBlob(byte[] sig)
        {
            var fieldSize = sig.Length / 2;
            var r = sig.Take(fieldSize).ToArray();
            var s = sig.Skip(fieldSize).ToArray();
            using (var worker = new SshDataWorker())
            {
                worker.WriteMpint(r);
                worker.WriteMpint(s);
                return worker.ToByteArray();
            }
        }
    }
}
