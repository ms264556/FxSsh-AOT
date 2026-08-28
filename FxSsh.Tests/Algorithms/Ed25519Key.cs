using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using FxSsh.Algorithms;

namespace FxSsh.Tests.Algorithms;

/// <summary>
/// <c>ssh-ed25519</c> public key algorithm (RFC 8709).
/// </summary>
public class Ed25519Key(string key) : PublicKeyAlgorithm(key)
{
    private const string AlgorithmOid = "1.3.101.112"; // id-Ed25519

    private byte[] _seed = new byte[32];
    private byte[] _publicKey = new byte[32];

    public override string Name => "ssh-ed25519";

    public override string PublicKeyName => "ssh-ed25519";

    /// <summary>
    /// Generate a fresh Ed25519 key pair and return it as a PKCS#8 PEM, ready
    /// for <see cref="SshServer.AddHostKey"/>.
    /// </summary>
    public static string GenerateKeyPem()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            using (writer.PushSequence())
                writer.WriteObjectIdentifier(AlgorithmOid);
            using (writer.PushOctetString())
                writer.WriteOctetString(seed);
        }
        return PemEncoding.WriteString("PRIVATE KEY", writer.Encode());
    }

    public override void ImportKey(string key)
    {
        ArgumentNullException.ThrowIfNull(key);

        // PKCS#8 PrivateKeyInfo:
        //   SEQUENCE { INTEGER 0, SEQUENCE { OID id-Ed25519 },
        //              OCTET STRING { OCTET STRING { seed } } }
        var pemBytes = Encoding.ASCII.GetBytes(key);
        var pemString = Encoding.ASCII.GetString(pemBytes);
        var fields = PemEncoding.Find(pemString);
        var der = Convert.FromBase64String(pemString[fields.Base64Data]);

        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var pkInfo = reader.ReadSequence();
        pkInfo.ReadInteger();
        var algId = pkInfo.ReadSequence();
        if (algId.ReadObjectIdentifier() != AlgorithmOid)
            throw new CryptographicException("Key is not an Ed25519 key (expected id-Ed25519).");
        var inner = new AsnReader(pkInfo.ReadOctetString(), AsnEncodingRules.DER).ReadOctetString();

        if (inner.Length != 32)
            throw new CryptographicException("Ed25519 seed must be 32 bytes.");
        _seed = inner;
        _publicKey = Ed25519.PublicKeyFromSeed(_seed);
    }

    public override string ExportKey()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            using (writer.PushSequence())
                writer.WriteObjectIdentifier(AlgorithmOid);
            using (writer.PushOctetString())
                writer.WriteOctetString(_seed);
        }
        return PemEncoding.WriteString("PRIVATE KEY", writer.Encode());
    }

    public override void LoadKeyAndCertificatesData(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        var reader = new SshDataReader(data);
        if (reader.ReadString(Encoding.ASCII) != PublicKeyName)
            throw new CryptographicException("Key and certificates were not created with this algorithm.");

        var publicKey = reader.ReadBinary();
        if (publicKey.Length != 32)
            throw new CryptographicException("Ed25519 public key must be 32 bytes.");
        _publicKey = publicKey;
    }

    public override byte[] CreateKeyAndCertificatesData()
    {
        return new SshDataWriter(4 + PublicKeyName.Length + 4 + _publicKey.Length)
            .Write(PublicKeyName, Encoding.ASCII)
            .WriteBinary(_publicKey)
            .ToByteArray();
    }

    public override bool VerifyData(byte[] data, byte[] signature)
        => Ed25519.Verify(data, _publicKey, signature);

    public override bool VerifyHash(byte[] hash, byte[] signature)
        => Ed25519.Verify(hash, _publicKey, signature);

    public override byte[] SignData(byte[] data)
        => Ed25519.Sign(data, _seed);

    public override byte[] SignHash(byte[] hash)
        => Ed25519.Sign(hash, _seed);
}
