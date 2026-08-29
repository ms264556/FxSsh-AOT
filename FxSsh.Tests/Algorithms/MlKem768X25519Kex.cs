using System;
using System.IO;
using System.Security.Cryptography;
using FxSsh.Algorithms;

namespace FxSsh.Tests.Algorithms;

/// <summary>
/// <c>mlkem768x25519-sha256</c> key exchange.
/// <para>ML-KEM-768 (FIPS 203) + X25519 KEX from OpenSSH (9.9+, default since 10.0)</para>
/// <para>The X25519 half uses the BCL <see cref="X25519DiffieHellman"/>.</para>
/// </summary>
public class MlKem768X25519Kex : KexAlgorithm
{
    public const string Name = "mlkem768x25519-sha256";

    private const int X25519Bytes = 32;
    private const int MlKemPublicKeyBytes = 1184;
    private const int MlKemCiphertextBytes = 1088;

    // TODO: make kex IDisposable (KexAlgorithm + this class) so the X25519DiffieHellman
    // and SHA256 instances are disposed deterministically when Session drops the kex.
    private readonly X25519DiffieHellman _x25519;

    /// <summary>Server X25519 public key (32 bytes).</summary>
    private readonly byte[] _x25519PublicKey;

    /// <summary>S_CT2 (ML-KEM-768 ciphertext), produced by DecryptKeyExchange.</summary>
    private byte[]? _serverCiphertext;

    public MlKem768X25519Kex()
    {
        if (!MLKem.IsSupported)
            throw new PlatformNotSupportedException("ML-KEM (FIPS 203) is not supported on this platform.");

        _x25519 = X25519DiffieHellman.GenerateKey();
        _x25519PublicKey = _x25519.ExportPublicKey();

        _hashAlgorithm = SHA256.Create();
    }

    /// <summary>
    /// The hybrid K carries its hash output as an SSH string in the exchange
    /// hash and in key derivation (RFC 4253 section 7.2), not as the mpint
    /// used by classical ECDH methods.
    /// </summary>
    public override bool SharedSecretIsString => true;

    /// <summary>
    /// Assemble S_REPLY = S_CT2 || S_PK1. Must be called after
    /// <see cref="DecryptKeyExchange"/> has produced the ciphertext.
    /// </summary>
    public override byte[] CreateKeyExchange()
    {
        if (_serverCiphertext == null)
            throw new InvalidOperationException("DecryptKeyExchange must be called before CreateKeyExchange.");

        var reply = new byte[_serverCiphertext.Length + _x25519PublicKey.Length];
        _serverCiphertext.CopyTo(reply, 0);
        _x25519PublicKey.CopyTo(reply, _serverCiphertext.Length);
        return reply;
    }

    /// <summary>
    /// Parse C_INIT = C_PK2 (ML-KEM-768 encapsulation key, 1184 B) || C_PK1 (X25519 pub, 32 B),
    /// encapsulate to the client's ML-KEM-768 key (yielding S_CT2 and K_PQ), derive the
    /// X25519 secret K_CL, and return K = SHA256(K_PQ || K_CL) as raw 32-byte hash output.
    /// </summary>
    public override byte[] DecryptKeyExchange(byte[] exchangeData)
    {
        ArgumentNullException.ThrowIfNull(exchangeData);

        if (exchangeData.Length != MlKemPublicKeyBytes + X25519Bytes)
            throw new InvalidDataException("C_INIT length does not match mlkem768x25519-sha256.");

        var mlkemPk = exchangeData.AsMemory(0, MlKemPublicKeyBytes);
        var clientX25519 = exchangeData.AsMemory(MlKemPublicKeyBytes, X25519Bytes).ToArray();

        // Server role: encapsulate to the client's ML-KEM key.
        byte[] kemSecret;
        byte[] ciphertext;
        using (var kem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, mlkemPk.Span))
        {
            ciphertext = new byte[MlKemCiphertextBytes];
            kemSecret = new byte[MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes];
            kem.Encapsulate(ciphertext, kemSecret);
        }

        var x25519Shared = _x25519.DeriveRawSecretAgreement(clientX25519);
        if (IsAllZero(x25519Shared))
            throw new InvalidOperationException("mlkem768x25519: X25519 produced an all-zero shared secret.");

        // Only commit the ciphertext to the state machine after every
        // validation has passed, so a failed exchange leaves the object clean
        // and CreateKeyExchange still refuses to run.
        _serverCiphertext = ciphertext;

        // K = SHA-256(kem_secret || x25519_shared), 32 bytes.
        return SHA256.HashData([.. kemSecret, .. x25519Shared]);
    }

    private static bool IsAllZero(byte[] data)
    {
        foreach (var b in data)
            if (b != 0) return false;
        return true;
    }
}
