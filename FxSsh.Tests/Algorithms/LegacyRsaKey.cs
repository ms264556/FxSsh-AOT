using System;
using System.Security.Cryptography;
using System.Text;
using FxSsh.Algorithms;

namespace FxSsh.Tests.Algorithms;

/// <summary>
/// Deprecated: legacy "ssh-rsa" public key algorithm, which uses SHA-1 for signatures.
/// <para>Kept only for interop with ancient clients - OpenSSH disabled SHA-1 signatures by
/// default in 8.8 and removed them entirely in 10.0.</para>
/// </summary>
[Obsolete("ssh-rsa uses SHA-1 signatures, disabled by default since OpenSSH 8.8 and removed in 10.0; use rsa-sha2-256/rsa-sha2-512 or ssh-ed25519.")]
public class LegacyRsaKey : PublicKeyAlgorithm
{
    private readonly RSA _algorithm = RSA.Create();

    /// <summary>
    /// Initializes a new instance of the <see cref="LegacyRsaKey"/> class.
    /// </summary>
    /// <param name="key">A PEM-formatted PKCS#8 private key string.</param>
    public LegacyRsaKey(string key)
        : base(key)
    {
    }

    /// <summary>
    /// Gets the name of the public key algorithm: "ssh-rsa".
    /// </summary>
    public override string Name => "ssh-rsa";

    /// <summary>
    /// Gets the name of the key format as used in the SSH protocol: "ssh-rsa".
    /// </summary>
    public override string PublicKeyName => "ssh-rsa";

    /// <summary>
    /// Imports the private key from a PEM-formatted string.
    /// </summary>
    /// <param name="key">The PEM-formatted PKCS#8 private key.</param>
    public override void ImportKey(string key)
    {
        _algorithm.ImportFromPem(key);
    }

    /// <summary>
    /// Exports the private key to a PEM-formatted PKCS#8 string.
    /// </summary>
    /// <returns>The PEM-formatted private key.</returns>
    public override string ExportKey()
    {
        return _algorithm.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>
    /// Loads the public key data from the SSH wire format.
    /// </summary>
    /// <param name="data">The byte array containing the SSH public key data.</param>
    public override void LoadKeyAndCertificatesData(byte[] data)
    {
        var reader = new SshDataReader(data);
        if (reader.ReadString(Encoding.ASCII) != PublicKeyName)
            throw new CryptographicException("Key and certificates were not created with this algorithm.");

        var args = new RSAParameters
        {
            Exponent = reader.ReadMpint(),
            Modulus = reader.ReadMpint(),
        };

        _algorithm.ImportParameters(args);
    }

    /// <summary>
    /// Creates the public key data in the SSH wire format.
    /// </summary>
    /// <returns>A byte array representing the public key.</returns>
    public override byte[] CreateKeyAndCertificatesData()
    {
        var args = _algorithm.ExportParameters(false);
        return new SshDataWriter(8 + PublicKeyName.Length + args.Exponent!.Length + args.Modulus!.Length)
            .Write(PublicKeyName, Encoding.ASCII)
            .WriteMpint(args.Exponent)
            .WriteMpint(args.Modulus)
            .ToByteArray();
    }

    /// <summary>
    /// Verifies the signature for the given data using SHA-1.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public override bool VerifyData(byte[] data, byte[] signature)
    {
        // The legacy "ssh-rsa" algorithm uses SHA-1 for the signature hash.
        return _algorithm.VerifyData(data, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Verifies the signature for the given hash using SHA-1.
    /// </summary>
    /// <param name="hash">The hash of the data to verify.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        // The legacy "ssh-rsa" algorithm uses SHA-1 for the signature hash.
        return _algorithm.VerifyHash(hash, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Creates a signature for the given data using SHA-1.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <returns>The signature for the data.</returns>
    public override byte[] SignData(byte[] data)
    {
        // The legacy "ssh-rsa" algorithm uses SHA-1 for the signature hash.
        return _algorithm.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Creates a signature for the given hash using SHA-1.
    /// </summary>
    /// <param name="hash">The hash of the data to sign.</param>
    /// <returns>The signature for the hash.</returns>
    public override byte[] SignHash(byte[] hash)
    {
        // The legacy "ssh-rsa" algorithm uses SHA-1 for the signature hash.
        return _algorithm.SignHash(hash, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
    }
}
