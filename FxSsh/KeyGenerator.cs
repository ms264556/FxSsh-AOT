using System;
using System.Security.Cryptography;

namespace FxSsh
{
    public static class KeyGenerator
    {
        public static string GenerateRsaKeyPem(int bitlen)
        {
            if (bitlen != 2048 && bitlen != 4096 && bitlen != 8192)
                throw new ArgumentOutOfRangeException(nameof(bitlen), bitlen, "Bit length must be 2048, 4096 or 8192.");

            var rsa = RSA.Create(bitlen);
            return rsa.ExportPkcs8PrivateKeyPem();
        }

        public static string GenerateECDsaKeyPem(string curveName)
        {
            if (curveName != "nistp256" && curveName != "nistp384" && curveName != "nistp521")
                throw new ArgumentOutOfRangeException(nameof(curveName), curveName, "Curve name must be nistp256, nistp384 or nistp521.");

            var curve = default(ECCurve);
            if (curveName == "nistp256") curve = ECCurve.NamedCurves.nistP256;
            else if (curveName == "nistp384") curve = ECCurve.NamedCurves.nistP384;
            else if (curveName == "nistp521") curve = ECCurve.NamedCurves.nistP521;
            var ecdsa = ECDsa.Create(curve);
            return ecdsa.ExportPkcs8PrivateKeyPem();
        }

        public static string ConvertRsaBase64KeyToPem(string oldBase64Key)
        {
            ArgumentNullException.ThrowIfNull(oldBase64Key);

            var rsa = new RSACryptoServiceProvider();
            var bytes = Convert.FromBase64String(oldBase64Key);
            rsa.ImportCspBlob(bytes);
            var pem = rsa.ExportPkcs8PrivateKeyPem();
            return pem;
        }
    }
}
