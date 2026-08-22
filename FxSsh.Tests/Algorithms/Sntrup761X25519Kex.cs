using System;
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

    // S_CT, produced by DecryptKeyExchange and consumed by CreateKeyExchange
    // when assembling S_REPLY = S_CT || S_PK1 (RFC 4253 / OpenSSH hybrid KEX).
    private byte[]? _serverCiphertext;

    public Sntrup761X25519Kex()
    {
        _x25519 = X25519DiffieHellman.GenerateKey();
        _x25519PublicKey = _x25519.ExportPublicKey();

        _hashAlgorithm = SHA512.Create();
    }

    /// <summary>
    /// The hybrid K carries its hash output as an SSH string in the exchange
    /// hash and in key derivation (RFC 4253 section 7.2), not as the mpint
    /// used by classical ECDH/DH methods.
    /// </summary>
    public override bool SharedSecretIsString => true;

    /// <summary>
    /// Parse Q_C = ntru_pk (1158) || client x25519 pub (32), one SSH string;
    /// encapsulate to the client's NTRU key, derive the X25519 half, and
    /// return K = SHA-512(kem_secret || x25519_shared) as the raw 64-byte hash
    /// output (Session string-encodes it when SharedSecretIsString).
    /// </summary>
    public override byte[] DecryptKeyExchange(byte[] exchangeData)
    {
        if (exchangeData.Length != NtruPublicKeyBytes + X25519Bytes)
            throw new InvalidOperationException($"sntrup761x25519: Q_C must be {NtruPublicKeyBytes + X25519Bytes} bytes.");

        var ntruPk = exchangeData.AsSpan(0, NtruPublicKeyBytes).ToArray();
        var clientX25519 = exchangeData.AsSpan(NtruPublicKeyBytes, X25519Bytes).ToArray();

        var kemSecret = new byte[Sntrup761.SharedSecretBytes];
        var ciphertext = new byte[NtruCiphertextBytes];
        Sntrup761.Encapsulate(ntruPk, ciphertext, kemSecret);

        var x25519Shared = _x25519.DeriveRawSecretAgreement(clientX25519);
        if (IsAllZero(x25519Shared))
            throw new InvalidOperationException("sntrup761x25519: X25519 produced an all-zero shared secret.");

        // Only commit the ciphertext to the state machine after every
        // validation has passed, so a failed exchange leaves the object clean.
        _serverCiphertext = ciphertext;

        // K = SHA-512(kem_secret || x25519_shared), 64 bytes.
        return SHA512.HashData([.. kemSecret, .. x25519Shared]);
    }

    /// <summary>
    /// Assemble S_REPLY = S_CT (1039) || server x25519 pub (32), one SSH
    /// string. Must be called after <see cref="DecryptKeyExchange"/> has
    /// produced the ciphertext.
    /// </summary>
    public override byte[] CreateKeyExchange()
    {
        if (_serverCiphertext == null)
            throw new InvalidOperationException("DecryptKeyExchange must be called before CreateKeyExchange.");

        var blob = new byte[NtruCiphertextBytes + X25519Bytes];
        Buffer.BlockCopy(_serverCiphertext, 0, blob, 0, NtruCiphertextBytes);
        Buffer.BlockCopy(_x25519PublicKey, 0, blob, NtruCiphertextBytes, X25519Bytes);
        return blob;
    }

    private static bool IsAllZero(byte[] data)
    {
        foreach (var b in data)
            if (b != 0) return false;
        return true;
    }
}
