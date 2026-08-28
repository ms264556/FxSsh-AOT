using System;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace FxSsh.Tests.Algorithms;

/// <summary>
/// <c>sntrup761</c> KEM.
/// <para>Ported from supercop 20201130 (public domain, ernstein/Chuengsatiansup/Lange/van Vredendaal) <see href="https://github.com/openssh/openssh-portable/blob/master/sntrup761.c">as shipped by OpenSSH</see></para>
/// </summary>
internal static class Sntrup761
{
    public const int PublicKeyBytes = 1158;
    public const int CiphertextBytes = 1039;
    public const int SharedSecretBytes = 32;

    private const int P = 761;
    private const int Q = 4591;
    private const int Q12 = (Q - 1) / 2; // 2295
    private const int W = 286;
    private const int RoundedBytes = 1007;
    private const int SmallBytes = (P + 3) / 4; // 191
    private const int HashBytes = 32;

    /// <summary>Randomness source, mirroring the C reference's randombytes().</summary>
    public delegate void RandomFill(Span<byte> buffer);

    /// <summary>Crypto RNG fill - the default randomness source.</summary>
    public static readonly RandomFill CryptoRandom = RandomNumberGenerator.Fill;

    #region constant-time helpers

    /* from supercop-20201130/crypto_sort/int32/portable4/int32_minmax.inc */
    private static void Int32MinMax(ref int a, ref int b)
    {
        var ab = b ^ (long)a;
        var c = b - (long)a;
        c ^= ab & (c ^ b);
        c >>= 31;
        c &= ab;
        a ^= (int)c;
        b ^= (int)c;
    }

    /* SIMD minmax over the contiguous pair runs: (x[j], x[j + stride]) for j in [start, end).
       Integer min/max are constant-time on x86/ARM, so this preserves the sort's timing
       profile while running Vector<int>.Count pairs at once. */
    private static void Int32MinMaxSpan(Span<int> x, int start, int end, int stride)
    {
        var j = start;
        if (Vector.IsHardwareAccelerated)
        {
            var count = Vector<int>.Count;
            for (; j + count <= end; j += count)
            {
                ref var ra = ref MemoryMarshal.GetReference(x[j..]);
                ref var rb = ref MemoryMarshal.GetReference(x[(j + stride)..]);
                var a = Vector.LoadUnsafe(ref ra);
                var b = Vector.LoadUnsafe(ref rb);
                Vector.Min(a, b).StoreUnsafe(ref ra);
                Vector.Max(a, b).StoreUnsafe(ref rb);
            }
        }
        for (; j < end; ++j) Int32MinMax(ref x[j], ref x[j + stride]);
    }

    /* from supercop-20201130/crypto_sort/int32/portable4/sort.c */
    private static void SortInt32(Span<int> x)
    {
        // n <= 761 here, so plain int indices are safe (the C code uses long long).
        var n = x.Length;
        int p;

        if (n < 2) return;
        var top = 1;
        while (top < n - top) top += top;

        for (p = top; p >= 1; p >>= 1)
        {
            var i = 0;
            while (i + 2 * p <= n)
            {
                Int32MinMaxSpan(x, i, i + p, p);
                i += 2 * p;
            }
            Int32MinMaxSpan(x, i, n - p, p);

            i = 0;
            var j = 0;
            int q;
            for (q = top; q > p; q >>= 1)
            {
                int r;
                if (j != i) for (;;)
                {
                    if (j == n - q) goto done;
                    var a = x[j + p];
                    for (r = q; r > p; r >>= 1)
                        Int32MinMax(ref a, ref x[j + r]);
                    x[j + p] = a;
                    ++j;
                    if (j != i + p) continue;
                    i += 2 * p;
                    break;
                }
                while (i + p <= n - q)
                {
                    for (j = i; j < i + p; ++j)
                    {
                        var a = x[j + p];
                        for (r = q; r > p; r >>= 1)
                            Int32MinMax(ref a, ref x[j + r]);
                        x[j + p] = a;
                    }
                    i += 2 * p;
                }
                /* now i + p > n - q */
                j = i;
                while (j < n - q)
                {
                    var a = x[j + p];
                    for (r = q; r > p; r >>= 1)
                        Int32MinMax(ref a, ref x[j + r]);
                    x[j + p] = a;
                    ++j;
                }

                done:;
            }
        }
    }

    /* from supercop-20201130/crypto_sort/uint32/useint32/sort.c */
    private static void SortUint32(Span<uint> x)
    {
        for (var j = 0; j < x.Length; ++j) x[j] ^= 0x80000000u;
        SortInt32(MemoryMarshal.Cast<uint, int>(x));
        for (var j = 0; j < x.Length; ++j) x[j] ^= 0x80000000u;
    }

    /* from supercop-20201130/crypto_kem/sntrup761/ref/uint32.c */
    private static void Uint32DivmodUint14(uint x, ushort m, out uint q, out ushort r)
    {
        // caller guarantees m > 0 and m < 16384
        var v = 0x80000000;

        v /= m;

        q = 0;

        var qpart = (uint)((x * (ulong)v) >> 31);
        x -= qpart * m; q += qpart;

        qpart = (uint)((x * (ulong)v) >> 31);
        x -= qpart * m; q += qpart;

        x -= m; q += 1;
        var mask = (uint)(-(int)(x >> 31));
        x += mask & m; q += mask;

        r = (ushort)x;
    }

    private static ushort ModUint14(uint x, ushort m)
    {
        Uint32DivmodUint14(x, m, out _, out var r);
        return r;
    }

    #endregion

    #region arithmetic mod 3 and mod q

    /* F3 is always represented as -1,0,1; x must not be close to top int16.
       The divisors 3 and Q are compile-time constants, so the JIT emits the
       Granlund-Montgomery magic-multiply sequence (no idiv) and both reductions
       are branchless: for C# % the result keeps the dividend's sign, so a single
       masked correction maps it onto the mathematical residue the C code uses. */
    private static sbyte F3Freeze(int x)
    {
        var r = (x + 1) % 3;        /* [-2, 2] */
        r += (r >> 31) & 3;         /* to [0, 2] */
        return (sbyte)(r - 1);      /* to [-1, 1] */
    }

    /* x must not be close to top int32 */
    private static short FqFreeze(int x)
    {
        var r = x % Q;              /* (-Q, Q) */
        r += ((r + Q12) >> 31) & Q;         /* add Q if r < -Q12 */
        r += ((Q12 - r) >> 31) & -Q;        /* subtract Q if r > Q12 */
        return (short)r;
    }

    #endregion

    #region polynomials mod q

    /* h = f*g in the ring Rq */
    private static void RqMultSmall(Span<short> h, ReadOnlySpan<short> f, ReadOnlySpan<sbyte> g)
    {
        // Raw linear convolution, reduced once per coefficient. Callers pass frozen f
        // (|f[i]| <= Q12 = 2295) and g in {-1,0,1}, so |acc[i]| <= 761*2295 << 2^31 and
        // the sum-then-reduce result is identical to the reference's per-step FqFreeze.
        Span<int> fi = stackalloc int[P];
        Span<int> acc = stackalloc int[P + P - 1];
        for (var i = 0; i < P; ++i) fi[i] = f[i];
        for (var j = 0; j < P; ++j)
        {
            var gj = (int)g[j];
            if (gj == 0) continue;
            var accJ = acc.Slice(j, P);
            var i = 0;
            if (Vector.IsHardwareAccelerated)
            {
                var count = Vector<int>.Count;
                for (; i + count <= P; i += count)
                {
                    var vf = Vector.LoadUnsafe(ref MemoryMarshal.GetReference(fi[i..]));
                    ref var ra = ref MemoryMarshal.GetReference(accJ[i..]);
                    var va = Vector.LoadUnsafe(ref ra);
                    (gj == 1 ? va + vf : va - vf).StoreUnsafe(ref ra);
                }
            }
            for (; i < P; ++i) accJ[i] += fi[i] * gj;
        }
        for (var i = 0; i < P - 1; ++i)
        {
            acc[i] += acc[i + P];
            acc[i + 1] += acc[i + P];
        }
        for (var i = 0; i < P; ++i) h[i] = FqFreeze(acc[i]);
    }

    #endregion

    #region rounded polynomials, randomness, hash

    private static void Round(Span<short> @out, ReadOnlySpan<short> a)
    {
        for (var i = 0; i < P; ++i) @out[i] = (short)(a[i] - F3Freeze(a[i]));
    }

    /* sorting to generate short polynomial */
    private static void ShortFromList(Span<sbyte> @out, ReadOnlySpan<uint> @in)
    {
        Span<uint> ls = stackalloc uint[P];

        for (var i = 0; i < W; ++i) ls[i] = @in[i] & 0xFFFFFFFE;
        for (var i = W; i < P; ++i) ls[i] = (@in[i] & 0xFFFFFFFD) | 1;
        SortUint32(ls);
        for (var i = 0; i < P; ++i) @out[i] = (sbyte)((ls[i] & 3) - 1);
    }

    /* e.g., b = 0 means out = Hash0(in); first 32 bytes of SHA-512(b || in) */
    private static void HashPrefix(Span<byte> out32, int b, ReadOnlySpan<byte> input)
    {
        Span<byte> x = stackalloc byte[input.Length + 1];
        x[0] = (byte)b;
        input.CopyTo(x[1..]);
        Span<byte> h = stackalloc byte[64];
        SHA512.HashData(x, h);
        h[..32].CopyTo(out32);
    }

    private static void ShortRandom(Span<sbyte> @out, RandomFill rng)
    {
        // One rng call for the whole buffer instead of 761 per-word calls. The words are
        // consumed in the same little-endian order as the reference's Urandom32.
        Span<uint> ls = stackalloc uint[P];
        rng(MemoryMarshal.AsBytes(ls));
        ShortFromList(@out, ls);
    }

    #endregion

    #region Streamlined NTRU Prime core

    /* c = Encrypt(r,h) */
    private static void Encrypt(Span<short> c, ReadOnlySpan<sbyte> r, ReadOnlySpan<short> h)
    {
        Span<short> hr = stackalloc short[P];

        RqMultSmall(hr, h, r);
        Round(c, hr);
    }
    
    #endregion

    #region Encode / Decode (supercop ref Encode.c / Decode.c)

    /* 0 <= R[i] < M[i] < 16384 */
    private static void Encode(Span<byte> @out, ref int outPos, ReadOnlySpan<ushort> rs, ReadOnlySpan<ushort> ms, int len)
    {
        if (len == 1)
        {
            var r = rs[0];
            var m = ms[0];
            while (m > 1)
            {
                @out[outPos++] = (byte)r;
                r >>= 8;
                m = (ushort)((m + 255) >> 8);
            }
            return;
        }

        Span<ushort> rs2 = stackalloc ushort[(len + 1) / 2];
        Span<ushort> ms2 = stackalloc ushort[(len + 1) / 2];

        int i;
        for (i = 0; i < len - 1; i += 2)
        {
            uint m0 = ms[i];
            var r = rs[i] + rs[i + 1] * m0;
            var m = ms[i + 1] * m0;
            while (m >= 16384)
            {
                @out[outPos++] = (byte)r;
                r >>= 8;
                m = (m + 255) >> 8;
            }

            rs2[i / 2] = (ushort)r;
            ms2[i / 2] = (ushort)m;
        }

        if (i < len)
        {
            rs2[i / 2] = rs[i];
            ms2[i / 2] = ms[i];
        }

        Encode(@out, ref outPos, rs2, ms2, (len + 1) / 2);
    }

    /* assumes 0 < M[i] < 16384; produces 0 <= R[i] < M[i] */
    private static void Decode(Span<ushort> @out, ReadOnlySpan<byte> s, ref int inPos, ReadOnlySpan<ushort> ms, int len)
    {
        switch (len)
        {
            case 1 when ms[0] == 1:
                @out[0] = 0;
                break;
            case 1 when ms[0] <= 256:
                @out[0] = ModUint14(s[inPos], ms[0]);
                inPos += 1;
                break;
            case 1:
                @out[0] = ModUint14((uint)(s[inPos] + (s[inPos + 1] << 8)), ms[0]);
                inPos += 2;
                break;
            case > 1:
            {
                Span<ushort> rs2 = stackalloc ushort[(len + 1) / 2];
                Span<ushort> ms2 = stackalloc ushort[(len + 1) / 2];
                Span<uint> bottomr = stackalloc uint[len / 2];
                Span<uint> bottomt = stackalloc uint[len / 2];

                int i;
                for (i = 0; i < len - 1; i += 2)
                {
                    var m = ms[i] * (uint)ms[i + 1];
                    if (m > 256 * 16383)
                    {
                        bottomt[i / 2] = 256 * 256;
                        bottomr[i / 2] = s[inPos] + 256u * s[inPos + 1];
                        inPos += 2;
                        ms2[i / 2] = (ushort)((((m + 255) >> 8) + 255) >> 8);
                    }
                    else if (m >= 16384)
                    {
                        bottomt[i / 2] = 256;
                        bottomr[i / 2] = s[inPos];
                        inPos += 1;
                        ms2[i / 2] = (ushort)((m + 255) >> 8);
                    }
                    else
                    {
                        bottomt[i / 2] = 1;
                        bottomr[i / 2] = 0;
                        ms2[i / 2] = (ushort)m;
                    }
                }
                if (i < len)
                    ms2[i / 2] = ms[i];
                Decode(rs2, s, ref inPos, ms2, (len + 1) / 2);
                for (i = 0; i < len - 1; i += 2)
                {
                    var r = bottomr[i / 2];
                    r += bottomt[i / 2] * rs2[i / 2];
                    Uint32DivmodUint14(r, ms[i], out var r1, out var r0);
                    r1 = ModUint14(r1, ms[i + 1]); /* only needed for invalid inputs */
                    @out[i] = r0;
                    @out[i + 1] = (ushort)r1;
                }
                if (i < len)
                    @out[i] = rs2[i / 2];
                break;
            }
        }
    }

    #endregion

    #region encoding of polynomials

    private static void RqDecode(Span<short> r, ReadOnlySpan<byte> s)
    {
        Span<ushort> rs = stackalloc ushort[P];
        Span<ushort> ms = stackalloc ushort[P];
        for (var i = 0; i < P; ++i) ms[i] = Q;
        var pos = 0;
        Decode(rs, s, ref pos, ms, P);
        for (var i = 0; i < P; ++i) r[i] = (short)(rs[i] - Q12);
    }

    private static void RoundedEncode(Span<byte> s, ReadOnlySpan<short> r)
    {
        Span<ushort> rs = stackalloc ushort[P];
        Span<ushort> ms = stackalloc ushort[P];
        for (var i = 0; i < P; ++i)
        {
            rs[i] = (ushort)(((r[i] + Q12) * 10923) >> 15);
            ms[i] = (Q + 2) / 3;
        }
        var pos = 0;
        Encode(s, ref pos, rs, ms, P);
    }

    /* encoding small polynomials (including short polynomials); p mod 4 = 1 */
    private static void SmallEncode(Span<byte> s, ref int pos, ReadOnlySpan<sbyte> f)
    {
        int x;
        for (var i = 0; i < P / 4; ++i)
        {
            x = f[i * 4] + 1;
            x += (f[i * 4 + 1] + 1) << 2;
            x += (f[i * 4 + 2] + 1) << 4;
            x += (f[i * 4 + 3] + 1) << 6;
            s[pos++] = (byte)x;
        }
        x = f[P - 1] + 1;
        s[pos++] = (byte)x;
    }

    #endregion

    #region confirmation and session-key hashes

    /* h = HashConfirm(r_enc, pk, cache); cache is Hash4(pk) */
    private static void HashConfirm(Span<byte> h, ReadOnlySpan<byte> rEnc, ReadOnlySpan<byte> cache)
    {
        Span<byte> x = stackalloc byte[HashBytes * 2];

        HashPrefix(x[..HashBytes], 3, rEnc);
        cache.CopyTo(x[HashBytes..]);
        HashPrefix(h, 2, x);
    }

    /* k = HashSession(b, y, z) */
    private static void HashSession(Span<byte> k, int b, ReadOnlySpan<byte> y, ReadOnlySpan<byte> z)
    {
        Span<byte> x = stackalloc byte[HashBytes + CiphertextBytes];

        HashPrefix(x[..HashBytes], 3, y);
        z.CopyTo(x[HashBytes..]);
        HashPrefix(k, b, x);
    }
    
    #endregion

    #region Streamlined NTRU Prime encoding + KEM

    /* C = ZEncrypt(r,pk) */
    private static void ZEncrypt(Span<byte> c, ReadOnlySpan<sbyte> r, ReadOnlySpan<byte> pk)
    {
        Span<short> h = stackalloc short[P];
        Span<short> cc = stackalloc short[P];

        RqDecode(h, pk);
        Encrypt(cc, r, h);
        RoundedEncode(c, cc);
    }

    /* c = ct(1007) || confirm(32); r_enc = encoded r */
    private static void Hide(Span<byte> c, Span<byte> rEnc, ReadOnlySpan<sbyte> r, ReadOnlySpan<byte> pk, ReadOnlySpan<byte> cache)
    {
        var pos = 0;
        SmallEncode(rEnc, ref pos, r);
        ZEncrypt(c[..RoundedBytes], r, pk);
        Span<byte> confirm = stackalloc byte[HashBytes];
        HashConfirm(confirm, rEnc, cache);
        confirm.CopyTo(c[RoundedBytes..]);
    }

    /* c,k = Encap(pk) */
    private static void Encap(Span<byte> c, Span<byte> k, ReadOnlySpan<byte> pk, RandomFill rng)
    {
        Span<sbyte> r = stackalloc sbyte[P];
        Span<byte> rEnc = stackalloc byte[SmallBytes];
        Span<byte> cache = stackalloc byte[HashBytes];

        ShortRandom(r, rng);
        HashPrefix(cache, 4, pk);
        Hide(c, rEnc, r, pk, cache);
        HashSession(k, 1, rEnc, c);
    }
    
    #endregion

    #region public API

    /// <summary>
    /// Encapsulate to <paramref name="pk"/>: <paramref name="ct"/> receives the
    /// <see cref="CiphertextBytes"/>-byte ciphertext, <paramref name="k"/> the
    /// <see cref="SharedSecretBytes"/>-byte shared secret.
    /// </summary>
    public static void Encapsulate(byte[] pk, byte[] ct, byte[] k, RandomFill? rng = null)
    {
        ArgumentNullException.ThrowIfNull(pk);
        ArgumentNullException.ThrowIfNull(ct);
        ArgumentNullException.ThrowIfNull(k);
        if (pk.Length != PublicKeyBytes) throw new ArgumentException($"pk must be {PublicKeyBytes} bytes", nameof(pk));
        if (ct.Length != CiphertextBytes) throw new ArgumentException($"ct must be {CiphertextBytes} bytes", nameof(ct));
        if (k.Length != SharedSecretBytes) throw new ArgumentException($"k must be {SharedSecretBytes} bytes", nameof(k));
        Encap(ct, k, pk, rng ?? CryptoRandom);
    }

    #endregion
}
