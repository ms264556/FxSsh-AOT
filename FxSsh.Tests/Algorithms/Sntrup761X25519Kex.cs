using System;
using System.IO;
using System.Security.Cryptography;
using FxSsh.Algorithms;

namespace FxSsh.Tests.Algorithms;

/// <summary>
/// <c>sntrup761x25519-sha512@openssh.com</c> key exchange.
/// </summary>
public class Sntrup761X25519Kex : KexAlgorithm
{
    public const string Name = "sntrup761x25519-sha512@openssh.com";

    private const int X25519Bytes = 32;
    private const int NtruPublicKeyBytes = Sntrup761.PublicKeyBytes;   // 1158
    private const int NtruCiphertextBytes = Sntrup761.CiphertextBytes; // 1039

    private readonly X25519DiffieHellman _x25519;
    private readonly byte[] _x25519PublicKey;

    /// <summary>S_CT2 (sntrup761 ciphertext), produced by DecryptKeyExchange.</summary>
    private byte[]? _serverCiphertext;

    public Sntrup761X25519Kex()
    {
        _x25519 = X25519DiffieHellman.GenerateKey();
        _x25519PublicKey = _x25519.ExportPublicKey();

        _hashAlgorithm = SHA512.Create();
    }

    /// <summary>
    /// The hybrid K is carried in the exchange hash and in key derivation as an
    /// SSH string, not the mpint used by classical ECDH methods.
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
    /// Parse C_INIT = ntru_pk (1158) || client x25519 pub (32), encapsulate to the
    /// client's NTRU key, derive the X25519 secret, and return
    /// K = SHA-512(kem_secret || x25519_shared) as raw 64-byte hash output.
    /// </summary>
    public override byte[] DecryptKeyExchange(byte[] exchangeData)
    {
        ArgumentNullException.ThrowIfNull(exchangeData);

        if (exchangeData.Length != NtruPublicKeyBytes + X25519Bytes)
            throw new InvalidDataException("C_INIT length does not match sntrup761x25519-sha512@openssh.com.");

        var ntruPk = exchangeData.AsSpan(0, NtruPublicKeyBytes).ToArray();
        var clientX25519 = exchangeData.AsSpan(NtruPublicKeyBytes, X25519Bytes).ToArray();

        // Server role: encapsulate to the client's NTRU key.
        var kemSecret = new byte[Sntrup761.SharedSecretBytes];
        var ciphertext = new byte[NtruCiphertextBytes];
        Sntrup761.Encapsulate(ntruPk, ciphertext, kemSecret);

        var x25519Shared = _x25519.DeriveRawSecretAgreement(clientX25519);
        if (IsAllZero(x25519Shared))
            throw new InvalidOperationException("sntrup761x25519: X25519 produced an all-zero shared secret.");

        _serverCiphertext = ciphertext;

        // K = SHA-512(kem_secret || x25519_shared), 64 bytes.
        return SHA512.HashData([.. kemSecret, .. x25519Shared]);
    }

    private static bool IsAllZero(byte[] data)
    {
        foreach (var b in data)
            if (b != 0) return false;
        return true;
    }
}
