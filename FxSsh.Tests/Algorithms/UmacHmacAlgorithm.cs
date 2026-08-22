using System;
using FxSsh.Algorithms;

namespace FxSsh.Tests.Algorithms;

/// <summary>
/// Deprecated: <c>umac-64@openssh.com</c> and <c>umac-128@openssh.com</c> Hmac Algorithm.
/// <para><b>Warning:</b> <c>umac-128</c> fails to negotiate with Windows 11 <c>ssh.exe</c> client.</para>
/// </summary>
[Obsolete("umac-* MACs are not supported by every client (umac-128 fails to negotiate with Windows 11 ssh.exe client); prefer hmac-sha2-256/hmac-sha2-512 (-etm).")]
public sealed class UmacHmacAlgorithm(byte[] key, int tagBytes) : HmacAlgorithm
{
    private readonly Umac _umac = new(key, tagBytes);

    public override int DigestLength => _umac.TagBytes;

    public override void ComputeHash(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, uint sequence, Span<byte> destination)
    {
        if (destination.Length < DigestLength)
            throw new ArgumentException("Destination too short for UMAC tag.", nameof(destination));
        _umac.Compute(a, b, sequence, destination[..DigestLength]);
    }
}
