using System;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;

namespace FxSsh
{
    public static class KeyGenerator
    {
        public static string GenerateRsaKeyPem(int bitlen)
        {
            Contract.Requires(bitlen == 2048 || bitlen == 4096 || bitlen == 8192);

            var rsa = RSA.Create(bitlen);
            return rsa.ExportPkcs8PrivateKeyPem();
        }

        public static string ConvertRsaBase64KeyToPem(string oldBase64Key)
        {
            Contract.Requires(oldBase64Key != null);

            var rsa = new RSACryptoServiceProvider();
            var bytes = Convert.FromBase64String(oldBase64Key);
            rsa.ImportCspBlob(bytes);
            var pem = rsa.ExportPkcs8PrivateKeyPem();
            return pem;
        }
    }
}
