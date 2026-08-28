using System;
using System.Numerics;
using System.Security.Cryptography;

namespace FxSsh.Tests.Algorithms;

/// <summary>
/// Ed25519 signatures (RFC 8032).
/// <para>ported from <see href="https://tweetnacl.cr.yp.to/">TweetNaCl</see> 20140427 (public domain, Bernstein et al.)</para>
/// </summary>
internal static class Ed25519
{
    /// <summary>Messages up to this size sign/verify with zero heap allocation.</summary>
    private const int MaxStackMessageBytes = 16 * 1024;

    #region constants (tweetnacl.c gf values)

    private static readonly long[] D = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
    private static readonly long[] D2 = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
    private static readonly long[] X = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
    private static readonly long[] Y = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
    private static readonly long[] I = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];

    /* group order L, little-endian 32 bytes */
    private static readonly long[] L = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];

    #endregion

    #region field arithmetic (tweetnacl.c gf ops)

    private static void Car25519(Span<long> o)
    {
        for (var i = 0; i < 16; i++)
        {
            o[i] += 1L << 16;
            var c = o[i] >> 16;
            o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i == 15 ? 1 : 0);
            o[i] -= c << 16;
        }
    }

    private static void Sel25519(Span<long> p, Span<long> q, int b)
    {
        var c = new Vector<long>(~(b - 1));
        var count = Vector<long>.Count;
        for (var i = 0; i < 16; i += count)
        {
            var vp = new Vector<long>(p.Slice(i, count));
            var vq = new Vector<long>(q.Slice(i, count));
            var t = c & (vp ^ vq);
            (vp ^ t).CopyTo(p.Slice(i, count));
            (vq ^ t).CopyTo(q.Slice(i, count));
        }
    }

    private static void Pack25519(Span<byte> o, ReadOnlySpan<long> n)
    {
        Span<long> m = stackalloc long[16];
        Span<long> t = stackalloc long[16];
        n.CopyTo(t);
        Car25519(t);
        Car25519(t);
        Car25519(t);
        for (var j = 0; j < 2; j++)
        {
            m[0] = t[0] - 0xffed;
            for (var i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            var b = (int)((m[15] >> 16) & 1);
            m[14] &= 0xffff;
            Sel25519(t, m, 1 - b);
        }
        for (var i = 0; i < 16; i++)
        {
            o[2 * i] = (byte)(t[i] & 0xff);
            o[2 * i + 1] = (byte)(t[i] >> 8);
        }
    }

    private static bool Neq25519(ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        Span<byte> c = stackalloc byte[32];
        Span<byte> d = stackalloc byte[32];
        Pack25519(c, a);
        Pack25519(d, b);
        return !CryptographicOperations.FixedTimeEquals(c, d);
    }

    private static int Par25519(ReadOnlySpan<long> a)
    {
        Span<byte> d = stackalloc byte[32];
        Pack25519(d, a);
        return d[0] & 1;
    }

    private static void Unpack25519(Span<long> o, ReadOnlySpan<byte> n)
    {
        for (var i = 0; i < 16; i++)
            o[i] = n[2 * i] + (n[2 * i + 1] << 8);
        o[15] &= 0x7fff;
    }

    private static void A(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        var count = Vector<long>.Count;
        for (var i = 0; i < 16; i += count)
        {
            var va = new Vector<long>(a.Slice(i, count));
            var vb = new Vector<long>(b.Slice(i, count));
            (va + vb).CopyTo(o.Slice(i, count));
        }
    }

    private static void Z(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        var count = Vector<long>.Count;
        for (var i = 0; i < 16; i += count)
        {
            var va = new Vector<long>(a.Slice(i, count));
            var vb = new Vector<long>(b.Slice(i, count));
            (va - vb).CopyTo(o.Slice(i, count));
        }
    }

    private static void M(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        var count = Vector<long>.Count;
        Span<long> t = stackalloc long[32];
        t.Clear();

        // schoolbook multiply, 16 limbs per vector lane group: t[i + j] += a[i] * b[j]
        for (var i = 0; i < 16; i++)
        {
            var ai = new Vector<long>(a[i]);
            for (var j = 0; j < 16; j += count)
            {
                var bj = new Vector<long>(b.Slice(j, count));
                var acc = new Vector<long>(t.Slice(i + j, count));
                (acc + ai * bj).CopyTo(t.Slice(i + j, count));
            }
        }

        // fold: t[i] += 38 * t[i + 16] for i < 16 (lane 15 sees t[31] == 0, a no-op)
        var c38 = new Vector<long>(38);
        for (var i = 0; i < 16; i += count)
        {
            var lo = new Vector<long>(t.Slice(i, count));
            var hi = new Vector<long>(t.Slice(i + 16, count));
            (lo + hi * c38).CopyTo(t.Slice(i, count));
        }

        t[..16].CopyTo(o);
        Car25519(o);
        Car25519(o);
    }

    private static void S(Span<long> o, ReadOnlySpan<long> a) => M(o, a, a);

    private static void Inv25519(Span<long> o, ReadOnlySpan<long> i)
    {
        Span<long> c = stackalloc long[16];
        i.CopyTo(c);
        for (var a = 253; a >= 0; a--)
        {
            S(c, c);
            if (a != 2 && a != 4) M(c, c, i);
        }
        c.CopyTo(o);
    }

    private static void Pow2523(Span<long> o, ReadOnlySpan<long> i)
    {
        Span<long> c = stackalloc long[16];
        i.CopyTo(c);
        for (var a = 250; a >= 0; a--)
        {
            S(c, c);
            if (a != 1) M(c, c, i);
        }
        c.CopyTo(o);
    }

    #endregion

    #region edwards point operations (tweetnacl.c)

    // A point is 4 field elements (X, Y, Z, T) packed into one 64-long span:
    // X = p[0..16), Y = p[16..32), Z = p[32..48), T = p[48..64).

    private static Span<long> Px(Span<long> p) => p[..16];
    private static Span<long> Py(Span<long> p) => p.Slice(16, 16);
    private static Span<long> Pz(Span<long> p) => p.Slice(32, 16);
    private static Span<long> Pt(Span<long> p) => p.Slice(48, 16);

    private static void Add(Span<long> p, Span<long> q)
    {
        Span<long> a = stackalloc long[16]; Span<long> b = stackalloc long[16]; Span<long> c = stackalloc long[16]; Span<long> d = stackalloc long[16];
        Span<long> t = stackalloc long[16]; Span<long> e = stackalloc long[16]; Span<long> f = stackalloc long[16]; Span<long> g = stackalloc long[16]; Span<long> h = stackalloc long[16];

        Z(a, Py(p), Px(p));
        Z(t, Py(q), Px(q));
        M(a, a, t);
        A(b, Px(p), Py(p));
        A(t, Px(q), Py(q));
        M(b, b, t);
        M(c, Pt(p), Pt(q));
        M(c, c, D2);
        M(d, Pz(p), Pz(q));
        A(d, d, d);
        Z(e, b, a);
        Z(f, d, c);
        A(g, d, c);
        A(h, b, a);

        M(Px(p), e, f);
        M(Py(p), h, g);
        M(Pz(p), g, f);
        M(Pt(p), e, h);
    }

    private static void Cswap(Span<long> p, Span<long> q, int b)
    {
        for (var i = 0; i < 4; i++)
            Sel25519(p.Slice(i * 16, 16), q.Slice(i * 16, 16), b);
    }

    private static void Pack(Span<byte> r, ReadOnlySpan<long> p)
    {
        Span<long> tx = stackalloc long[16];
        Span<long> ty = stackalloc long[16];
        Span<long> zi = stackalloc long[16];
        Inv25519(zi, p.Slice(32, 16));
        M(tx, p[..16], zi);
        M(ty, p.Slice(16, 16), zi);
        Pack25519(r, ty);
        r[31] ^= (byte)(Par25519(tx) << 7);
    }

    private static void Scalarmult(Span<long> p, Span<long> q, ReadOnlySpan<byte> s)
    {
        p.Clear();
        p[16] = 1; // Y = 1
        p[32] = 1; // Z = 1
        for (var i = 255; i >= 0; i--)
        {
            var b = (s[i / 8] >> (i & 7)) & 1;
            Cswap(p, q, b);
            Add(q, p);
            Add(p, p);
            Cswap(p, q, b);
        }
    }

    private static void Scalarbase(Span<long> p, ReadOnlySpan<byte> s)
    {
        Span<long> q = stackalloc long[64];
        q.Clear();
        X.AsSpan().CopyTo(q[..16]);
        Y.AsSpan().CopyTo(q.Slice(16, 16));
        q[32] = 1; // Z = 1
        M(q.Slice(48, 16), X, Y);
        Scalarmult(p, q, s);
    }

    private static int UnpackNeg(Span<long> r, ReadOnlySpan<byte> p)
    {
        Span<long> t = stackalloc long[16]; Span<long> chk = stackalloc long[16]; Span<long> num = stackalloc long[16];
        Span<long> den = stackalloc long[16]; Span<long> den2 = stackalloc long[16]; Span<long> den4 = stackalloc long[16]; Span<long> den6 = stackalloc long[16];

        r.Slice(32, 16).Clear();
        r[32] = 1; // Z = 1
        Unpack25519(r.Slice(16, 16), p);
        S(num, r.Slice(16, 16));
        M(den, num, D);
        Z(num, num, r.Slice(32, 16));
        A(den, r.Slice(32, 16), den);

        S(den2, den);
        S(den4, den2);
        M(den6, den4, den2);
        M(t, den6, num);
        M(t, t, den);

        Pow2523(t, t);
        M(t, t, num);
        M(t, t, den);
        M(t, t, den);
        M(r[..16], t, den);

        S(chk, r[..16]);
        M(chk, chk, den);
        if (Neq25519(chk, num)) M(r[..16], r[..16], I);

        S(chk, r[..16]);
        M(chk, chk, den);
        if (Neq25519(chk, num)) return -1;

        if (Par25519(r[..16]) == (p[31] >> 7))
        {
            Span<long> zero = stackalloc long[16];
            zero.Clear();
            Z(r[..16], zero, r[..16]);
        }

        M(r.Slice(48, 16), r[..16], r.Slice(16, 16));
        return 0;
    }

    #endregion

    #region scalars mod L (tweetnacl.c modL / reduce)

    private static void ModL(Span<byte> r, Span<long> x)
    {
        long carry;
        int i, j;
        for (i = 63; i >= 32; i--)
        {
            carry = 0;
            for (j = i - 32; j < i - 12; j++)
            {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                carry = (x[j] + 128) >> 8;
                x[j] -= carry << 8;
            }
            x[j] += carry;
            x[i] = 0;
        }
        carry = 0;
        for (j = 0; j < 32; j++)
        {
            x[j] += carry - (x[31] >> 4) * L[j];
            carry = x[j] >> 8;
            x[j] &= 255;
        }
        for (j = 0; j < 32; j++) x[j] -= carry * L[j];
        for (i = 0; i < 32; i++)
        {
            x[i + 1] += x[i] >> 8;
            r[i] = (byte)(x[i] & 255);
        }
    }

    private static void Reduce(Span<byte> r)
    {
        Span<long> x = stackalloc long[64];
        for (var i = 0; i < 64; i++) x[i] = r[i];
        r.Clear();
        ModL(r, x);
    }

    /// <summary>
    /// SHA-512 of part1 || part2 || part3 into <paramref name="destination"/>
    /// (must be 64 bytes). The concatenation buffer is stackalloc'd for small
    /// inputs and falls back to the heap above <see cref="MaxStackMessageBytes"/>.
    /// </summary>
    private static void HashConcat(Span<byte> destination, ReadOnlySpan<byte> part1, ReadOnlySpan<byte> part2, ReadOnlySpan<byte> part3)
    {
        var size = part1.Length + part2.Length + part3.Length;
        if (size <= MaxStackMessageBytes)
        {
            Span<byte> input = stackalloc byte[size];
            part1.CopyTo(input);
            part2.CopyTo(input[part1.Length..]);
            part3.CopyTo(input[(part1.Length + part2.Length)..]);
            SHA512.HashData(input, destination);
        }
        else
        {
            var input = new byte[size];
            part1.CopyTo(input);
            part2.CopyTo(input.AsSpan(part1.Length));
            part3.CopyTo(input.AsSpan(part1.Length + part2.Length));
            SHA512.HashData(input, destination);
        }
    }

    #endregion

    #region public API

    /// <summary>Derive the 32-byte Ed25519 public key from a 32-byte seed.</summary>
    public static byte[] PublicKeyFromSeed(byte[] seed)
    {
        if (seed.Length != 32)
            throw new ArgumentException("Ed25519 seed must be 32 bytes.", nameof(seed));

        Span<byte> d = stackalloc byte[64];
        SHA512.HashData(seed, d);
        d[0] &= 248;
        d[31] &= 127;
        d[31] |= 64;

        Span<long> p = stackalloc long[64];
        Scalarbase(p, d);

        var pk = new byte[32];
        Pack(pk, p);
        return pk;
    }

    /// <summary>
    /// Sign <paramref name="message"/> with a 32-byte Ed25519 seed, returning
    /// the 64-byte signature (R || S). Ed25519 hashes internally, so the
    /// message is signed directly - exactly how ssh-ed25519 signs the SSH
    /// exchange hash (RFC 8709).
    /// </summary>
    public static byte[] Sign(byte[] message, byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (seed.Length != 32)
            throw new ArgumentException("Ed25519 seed must be 32 bytes.", nameof(seed));

        Span<byte> d = stackalloc byte[64];
        SHA512.HashData(seed, d);
        d[0] &= 248;
        d[31] &= 127;
        d[31] |= 64;

        // r = H(d[32..64) || message), reduced mod L
        Span<byte> r = stackalloc byte[64];
        HashConcat(r, d.Slice(32, 32), message, default);
        Reduce(r);

        var sig = new byte[64];
        Span<long> p = stackalloc long[64];
        Scalarbase(p, r);
        Pack(sig, p); // R

        // pk (for h = H(R || pk || message)): re-derive from the clamped scalar.
        Span<byte> pk = stackalloc byte[32];
        Scalarbase(p, d);
        Pack(pk, p);

        // h = H(R || pk || message), reduced mod L
        Span<byte> h = stackalloc byte[64];
        HashConcat(h, sig.AsSpan(0, 32), pk, message);
        Reduce(h);

        // S = r + h * d mod L
        Span<long> x = stackalloc long[64];
        x.Clear();
        for (var i = 0; i < 32; i++) x[i] = r[i];
        for (var i = 0; i < 32; i++)
            for (var j = 0; j < 32; j++)
                x[i + j] += h[i] * (long)d[j];
        ModL(sig.AsSpan(32), x);

        return sig;
    }

    /// <summary>Verify a 64-byte Ed25519 signature over <paramref name="message"/>.</summary>
    public static bool Verify(byte[] message, byte[] publicKey, byte[] signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;

        Span<long> q = stackalloc long[64];
        if (UnpackNeg(q, publicKey) != 0) return false;

        // h = H(R || pk || message), reduced mod L
        Span<byte> h = stackalloc byte[64];
        HashConcat(h, signature.AsSpan(0, 32), publicKey, message);
        Reduce(h);

        // R = A * h + S * B  (crypto_sign_open: scalarmult(p, q, h) then
        // scalarbase(q, sm + 32) - the SECOND 32 bytes are the S scalar)
        Span<long> p = stackalloc long[64];
        Scalarmult(p, q, h);
        Span<byte> s = stackalloc byte[32];
        signature.AsSpan(32, 32).CopyTo(s);
        Scalarbase(q, s);
        Add(p, q);

        Span<byte> t = stackalloc byte[32];
        Pack(t, p);
        return CryptographicOperations.FixedTimeEquals(signature.AsSpan(0, 32), t);
    }

    #endregion
}
