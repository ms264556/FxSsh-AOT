using System.Numerics;
using System.Security.Cryptography;
using FxSsh.Algorithms;

namespace FxSsh.Tests.Algorithms;

/// <summary><c>curve25519-sha256</c> key exchange (RFC 8731).</summary>
public class Curve25519Kex : KexAlgorithm
{
    private readonly X25519DiffieHellman _x25519;
    private readonly byte[] _publicKey;

    public Curve25519Kex()
    {
        _x25519 = X25519DiffieHellman.GenerateKey();
        _publicKey = _x25519.ExportPublicKey();

        // Set hash algorithm to SHA-256 as specified
        _hashAlgorithm = SHA256.Create();
    }

    public override byte[] CreateKeyExchange()
    {
        // Return public key in little-endian format (RFC 7748)
        return _publicKey;
    }

    public override byte[] DecryptKeyExchange(byte[] exchangeData)
    {
        // Compute raw shared secret (little-endian)
        var sharedSecretBytes = _x25519.DeriveRawSecretAgreement(exchangeData);

        // Convert to BigInteger for proper MPI handling
        var k = new BigInteger(sharedSecretBytes, isUnsigned: true, isBigEndian: true);

        // Handle zero value specially (SSH requires empty MPI)
        return k.IsZero ? [] :
            // Convert to normalized big-endian MPI format
            k.ToByteArray(isUnsigned: false, isBigEndian: true);
    }
}
