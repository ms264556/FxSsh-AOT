using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using FxSsh.Algorithms;

namespace FxSsh.Tests.Algorithms;

/// <summary>
/// Per-packet AEAD transform implementing the <c>chacha20-poly1305@openssh.com</c>
/// cipher (<see href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">OpenSSH PROTOCOL, §1.7</see>).
/// </summary>
public sealed class ChaCha20Poly1305Transform : IAeadTransform
{
    /// <summary>Key size in bytes: two 256-bit keys from the key exchange.</summary>
    public const int KeySize = 64;

    /// <summary>AEAD tag size in bytes.</summary>
    public const int TagSize = 16;

    private readonly byte[] _key;
    // Native ChaCha20 for the bulk payload keystream (the same speed class as
    // AesGcm). The BCL AEAD's tag layout differs from the SSH construction, so
    // only its symmetric keystream is used and the SSH tag is computed
    // separately; null when the platform lacks support (falls back to the
    // vectorized kernel below).
    private readonly ChaCha20Poly1305? _payload;

    public ChaCha20Poly1305Transform(byte[] key)
        : this(key, forceManagedKeystream: false)
    {
    }

    /// <summary>
    /// <paramref name="forceManagedKeystream"/> disables the native BCL
    /// ChaCha20Poly1305 keystream and routes the payload through the
    /// vectorized kernel below - the code path taken on platforms without
    /// native ChaCha20. Used by tests.
    /// </summary>
    internal ChaCha20Poly1305Transform(byte[] key, bool forceManagedKeystream)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != KeySize)
            throw new ArgumentException($"chacha20-poly1305@openssh.com requires a {KeySize}-byte key (two 256-bit keys from the key exchange).", nameof(key));
        _key = key;
        if (!forceManagedKeystream)
        {
            try
            {
                _payload = new ChaCha20Poly1305(key.AsSpan(0, 32));
            }
            catch (PlatformNotSupportedException)
            {
                _payload = null;   // no native ChaCha20 on this platform
            }
        }
        else
        {
            _payload = null;
        }
    }

    public int TagBytes => TagSize;

    public int DecryptPacketLength(uint sequenceNumber, ReadOnlySpan<byte> encryptedLength)
    {
        Span<byte> plain = stackalloc byte[4];
        XorKeystream(_key.AsSpan(32, 32), sequenceNumber, blockCounter: 0, encryptedLength, plain);
        return (int)BinaryPrimitives.ReadUInt32BigEndian(plain);
    }

    public void Encrypt(uint sequenceNumber, ReadOnlySpan<byte> frame, Span<byte> destination)
    {
        // frame: [packet_length(4)][padding_length||payload||padding]
        // destination: [encrypted length(4)][ciphertext][tag(16)]
        if (destination.Length < frame.Length + TagSize)
            throw new ArgumentException("Destination too short for chacha20-poly1305 ciphertext and tag.", nameof(destination));

        Span<byte> polyKey = stackalloc byte[32];
        Span<byte> zeros = stackalloc byte[32];
        // block 0 -> Poly1305 key
        XorKeystream(_key.AsSpan(0, 32), sequenceNumber, blockCounter: 0, zeros, polyKey);
        // encrypted length
        XorKeystream(_key.AsSpan(32, 32), sequenceNumber, blockCounter: 0, frame[..4], destination[..4]);
        // blocks 1..
        XorPayload(sequenceNumber, frame[4..], destination[4..^TagSize]);

        Poly1305(polyKey, destination[..^TagSize], ReadOnlySpan<byte>.Empty, destination[^TagSize..]);
    }

    public void Decrypt(uint sequenceNumber, ReadOnlySpan<byte> lengthField, ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintextDestination)
    {
        // Tag checked BEFORE decryption (the point of the separately-keyed
        // length cipher: no decryption oracle for unauthenticated data).
        var ciphertextLength = ciphertextWithTag.Length - TagSize;
        Span<byte> polyKey = stackalloc byte[32];
        Span<byte> zeros = stackalloc byte[32];
        XorKeystream(_key.AsSpan(0, 32), sequenceNumber, blockCounter: 0, zeros, polyKey);

        Span<byte> expected = stackalloc byte[TagSize];
        Poly1305(polyKey, lengthField, ciphertextWithTag[..ciphertextLength], expected);
        if (!expected.SequenceEqual(ciphertextWithTag[ciphertextLength..]))
            throw new CryptographicException("Invalid chacha20-poly1305@openssh.com auth tag.");

        XorPayload(sequenceNumber, ciphertextWithTag[..ciphertextLength], plaintextDestination[..ciphertextLength]);
    }

    /// <summary>
    /// XOR the packet payload with the K1 keystream starting at block 1: via
    /// the native ChaCha20Poly1305 instance (its Encrypt is symmetric - same
    /// keystream, tag discarded) when available, otherwise via the vectorized
    /// kernel.
    /// </summary>
    private void XorPayload(uint sequenceNumber, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (_payload != null)
        {
            Span<byte> nonce = stackalloc byte[12];
            WriteNonce(sequenceNumber, nonce);
            Span<byte> scratchTag = stackalloc byte[TagSize];
            _payload.Encrypt(nonce, input, output, scratchTag, ReadOnlySpan<byte>.Empty);
        }
        else
        {
            XorKeystream(_key.AsSpan(0, 32), sequenceNumber, blockCounter: 1, input, output);
        }
    }

    /// <summary>
    /// The SSH per-packet nonce, mapped onto the IETF layout: 8 zero bytes
    /// followed by the sequence number as uint32 big-endian.
    /// </summary>
    private static void WriteNonce(uint sequenceNumber, Span<byte> nonce)
    {
        // SSH encodes the sequence number big-endian into the last four bytes of the nonce.
        BinaryPrimitives.WriteUInt32BigEndian(nonce[8..], sequenceNumber);
    }

    // ---- ChaCha20 ---------------------------------------------------------

    /// <summary>
    /// XOR <paramref name="input"/> with the ChaCha20 keystream for the given
    /// packet: key K, per-packet nonce from <paramref name="sequenceNumber"/>,
    /// starting at 64-byte block <paramref name="blockCounter"/> (0 = Poly1305
    /// key block, 1 = first payload block). Writes to <paramref name="output"/>.
    /// Uses the vectorized kernel when SIMD is available.
    /// </summary>
    private static void XorKeystream(ReadOnlySpan<byte> key, uint sequenceNumber, ulong blockCounter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (Vector.IsHardwareAccelerated && Vector<uint>.Count >= 4)
            XorKeystreamSimd(key, sequenceNumber, blockCounter, input, output);
        else
            XorKeystreamScalar(key, sequenceNumber, blockCounter, input, output);
    }

    private static void XorKeystreamScalar(ReadOnlySpan<byte> key, uint sequenceNumber, ulong blockCounter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        var offset = 0;
        while (offset < input.Length)
        {
            var n = Math.Min(64, input.Length - offset);
            ChaCha20XorBlock(key, sequenceNumber, blockCounter + (ulong)(offset >> 6), input.Slice(offset, n), output.Slice(offset, n));
            offset += n;
        }
    }

    private static void XorKeystreamSimd(ReadOnlySpan<byte> key, uint sequenceNumber, ulong blockCounter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        // Process Vector<uint>.Count 64-byte blocks per iteration (8 with
        // AVX2, 4 with SSE2/NEON); any trailing blocks go through the scalar
        // kernel (typical SSH packets are 8-byte multiples, so full 32 KiB
        // packets are entirely vectorized).
        var chunkBytes = Vector<uint>.Count * 64;
        var offset = 0;
        while (offset + chunkBytes <= input.Length)
        {
            ChaCha20XorBlocks(key, sequenceNumber, blockCounter + (ulong)(offset / 64), input.Slice(offset, chunkBytes), output.Slice(offset, chunkBytes));
            offset += chunkBytes;
        }
        while (offset < input.Length)
        {
            var n = Math.Min(64, input.Length - offset);
            ChaCha20XorBlock(key, sequenceNumber, blockCounter + (ulong)(offset >> 6), input.Slice(offset, n), output.Slice(offset, n));
            offset += n;
        }
    }

    /// <summary>
    /// One ChaCha20 keystream block (DJB's construction as used by OpenSSH's
    /// chacha.c) XORed into <paramref name="output"/>: state = constants ||
    /// key || blockCounter (words 12-13, little-endian) || iv (words 14-15).
    /// The iv is the SSH wire-encoded (big-endian) sequence number read
    /// little-endian, i.e. word 14 = 0 and word 15 = the byte-swapped number.
    /// The permutation runs on register locals; the keystream is written four
    /// bytes at a time with no intermediate block buffer.
    /// </summary>
    private static void ChaCha20XorBlock(ReadOnlySpan<byte> key, uint sequenceNumber, ulong blockCounter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        const uint j0 = 0x61707865u;
        const uint j1 = 0x3320646eu;
        const uint j2 = 0x79622d32u;
        const uint j3 = 0x6b206574u;
        var j4 = BinaryPrimitives.ReadUInt32LittleEndian(key);
        var j5 = BinaryPrimitives.ReadUInt32LittleEndian(key[4..]);
        var j6 = BinaryPrimitives.ReadUInt32LittleEndian(key[8..]);
        var j7 = BinaryPrimitives.ReadUInt32LittleEndian(key[12..]);
        var j8 = BinaryPrimitives.ReadUInt32LittleEndian(key[16..]);
        var j9 = BinaryPrimitives.ReadUInt32LittleEndian(key[20..]);
        var j10 = BinaryPrimitives.ReadUInt32LittleEndian(key[24..]);
        var j11 = BinaryPrimitives.ReadUInt32LittleEndian(key[28..]);
        var j12 = (uint)blockCounter;
        var j13 = (uint)(blockCounter >> 32);
        const uint j14 = 0u;
        var j15 = BinaryPrimitives.ReverseEndianness(sequenceNumber);

        var x0 = j0; var x1 = j1; var x2 = j2; var x3 = j3;
        var x4 = j4; var x5 = j5; var x6 = j6; var x7 = j7;
        var x8 = j8; var x9 = j9; var x10 = j10; var x11 = j11;
        var x12 = j12; var x13 = j13; var x14 = j14; var x15 = j15;

        for (var round = 0; round < 10; round++)
        {
            QuarterRound(ref x0, ref x4, ref x8, ref x12);
            QuarterRound(ref x1, ref x5, ref x9, ref x13);
            QuarterRound(ref x2, ref x6, ref x10, ref x14);
            QuarterRound(ref x3, ref x7, ref x11, ref x15);
            QuarterRound(ref x0, ref x5, ref x10, ref x15);
            QuarterRound(ref x1, ref x6, ref x11, ref x12);
            QuarterRound(ref x2, ref x7, ref x8, ref x13);
            QuarterRound(ref x3, ref x4, ref x9, ref x14);
        }

        // XOR the completed keystream words into the output (n <= 64 here).
        var n = input.Length;
        Span<uint> stream = stackalloc uint[16];
        stream[0] = x0 + j0; stream[1] = x1 + j1; stream[2] = x2 + j2; stream[3] = x3 + j3;
        stream[4] = x4 + j4; stream[5] = x5 + j5; stream[6] = x6 + j6; stream[7] = x7 + j7;
        stream[8] = x8 + j8; stream[9] = x9 + j9; stream[10] = x10 + j10; stream[11] = x11 + j11;
        stream[12] = x12 + j12; stream[13] = x13 + j13; stream[14] = x14 + j14; stream[15] = x15 + j15;

        for (var w = 0; w < (n + 3) >> 2; w++)
        {
            var word = stream[w];
            var off = w << 2;
            var remain = n - off;
            if (remain >= 4)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(output[off..], word ^ BinaryPrimitives.ReadUInt32LittleEndian(input[off..]));
            }
            else
            {
                output[off] = (byte)(input[off] ^ (byte)word);
                if (remain > 1)
                {
                    output[off + 1] = (byte)(input[off + 1] ^ (byte)(word >> 8));
                    if (remain > 2)
                        output[off + 2] = (byte)(input[off + 2] ^ (byte)(word >> 16));
                }
            }
        }
    }

    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b; d = BitOperations.RotateLeft(d ^ a, 16);
        c += d; b = BitOperations.RotateLeft(b ^ c, 12);
        a += b; d = BitOperations.RotateLeft(d ^ a, 8);
        c += d; b = BitOperations.RotateLeft(b ^ c, 7);
    }

    /// <summary>
    /// Vectorized ChaCha20 kernel: processes Vector&lt;uint&gt;.Count 64-byte
    /// blocks in parallel (8 with AVX2, 4 with SSE2/NEON) using the classic
    /// block-transposed layout - SIMD lane b holds word i of block b, so the
    /// quarter rounds are pure lane-wise add/xor/rotate with no shuffles.
    /// The blocks differ only in their counter words (12-13), built per lane.
    /// </summary>
    private static void ChaCha20XorBlocks(ReadOnlySpan<byte> key, uint sequenceNumber, ulong startBlock, ReadOnlySpan<byte> input, Span<byte> output)
    {
        var blocks = Vector<uint>.Count;

        // Per-lane block counters: lane b encrypts block startBlock + b.
        Span<uint> counters = stackalloc uint[blocks];
        for (var b = 0; b < blocks; b++)
            counters[b] = (uint)(startBlock + (ulong)b);
        var ctr = Vector.Create(counters);

        var w0 = new Vector<uint>(0x61707865u);
        var w1 = new Vector<uint>(0x3320646eu);
        var w2 = new Vector<uint>(0x79622d32u);
        var w3 = new Vector<uint>(0x6b206574u);
        var w4 = new Vector<uint>(BinaryPrimitives.ReadUInt32LittleEndian(key));
        var w5 = new Vector<uint>(BinaryPrimitives.ReadUInt32LittleEndian(key[4..]));
        var w6 = new Vector<uint>(BinaryPrimitives.ReadUInt32LittleEndian(key[8..]));
        var w7 = new Vector<uint>(BinaryPrimitives.ReadUInt32LittleEndian(key[12..]));
        var w8 = new Vector<uint>(BinaryPrimitives.ReadUInt32LittleEndian(key[16..]));
        var w9 = new Vector<uint>(BinaryPrimitives.ReadUInt32LittleEndian(key[20..]));
        var w10 = new Vector<uint>(BinaryPrimitives.ReadUInt32LittleEndian(key[24..]));
        var w11 = new Vector<uint>(BinaryPrimitives.ReadUInt32LittleEndian(key[28..]));
        var w12 = ctr;
        var w13 = Vector<uint>.Zero;   // counter high word: always 0 for SSH block counts
        var w14 = Vector<uint>.Zero;   // iv high word: 0
        var w15 = new Vector<uint>(BinaryPrimitives.ReverseEndianness(sequenceNumber));

        var o0 = w0; var o1 = w1; var o2 = w2; var o3 = w3;
        var o4 = w4; var o5 = w5; var o6 = w6; var o7 = w7;
        var o8 = w8; var o9 = w9; var o10 = w10; var o11 = w11;
        var o12 = w12; var o13 = w13; var o14 = w14; var o15 = w15;

        for (var round = 0; round < 10; round++)
        {
            QuarterRound(ref w0, ref w4, ref w8, ref w12);
            QuarterRound(ref w1, ref w5, ref w9, ref w13);
            QuarterRound(ref w2, ref w6, ref w10, ref w14);
            QuarterRound(ref w3, ref w7, ref w11, ref w15);
            QuarterRound(ref w0, ref w5, ref w10, ref w15);
            QuarterRound(ref w1, ref w6, ref w11, ref w12);
            QuarterRound(ref w2, ref w7, ref w8, ref w13);
            QuarterRound(ref w3, ref w4, ref w9, ref w14);
        }

        // Add the initial state back (the final keystream words).
        Span<Vector<uint>> stream = stackalloc Vector<uint>[16];
        stream[0] = w0 + o0; stream[1] = w1 + o1; stream[2] = w2 + o2; stream[3] = w3 + o3;
        stream[4] = w4 + o4; stream[5] = w5 + o5; stream[6] = w6 + o6; stream[7] = w7 + o7;
        stream[8] = w8 + o8; stream[9] = w9 + o9; stream[10] = w10 + o10; stream[11] = w11 + o11;
        stream[12] = w12 + o12; stream[13] = w13 + o13; stream[14] = w14 + o14; stream[15] = w15 + o15;

        // De-transpose: block b's 64 bytes are stream[0][b] .. stream[15][b],
        // XORed into the output four bytes at a time.
        for (var b = 0; b < blocks; b++)
        {
            var blockOffset = b * 64;
            for (var i = 0; i < 16; i++)
            {
                var word = stream[i].GetElement(b);
                var off = blockOffset + i * 4;
                BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(off, 4),
                    word ^ BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(off, 4)));
            }
        }
    }

    private static void QuarterRound(ref Vector<uint> a, ref Vector<uint> b, ref Vector<uint> c, ref Vector<uint> d)
    {
        a += b; d = RotateLeft(d ^ a, 16);
        c += d; b = RotateLeft(b ^ c, 12);
        a += b; d = RotateLeft(d ^ a, 8);
        c += d; b = RotateLeft(b ^ c, 7);
    }

    private static Vector<uint> RotateLeft(Vector<uint> v, int n)
        => (v << n) | (v >> (32 - n));

    // ---- Poly1305 (donna/ref10: five 26-bit limbs in 64-bit registers) -----

    private const ulong M26 = 0x3ffffff;   // 2^26 - 1: limb mask

    /// <summary>
    /// Classic Poly1305 one-time MAC (RFC 8439 section 2.5, as used by the SSH
    /// draft: no AAD padding, no length encoding). r = key[0..16) clamped,
    /// s = key[16..32); each 16-byte message block gets a 0x01 byte appended
    /// (bit 128 set; a short final block keeps its short length);
    /// tag = (h + s) mod 2^128, little-endian.
    ///
    /// <paramref name="a"/> and <paramref name="b"/> are consecutive message
    /// segments (the 4-byte encrypted length and the ciphertext): a pending
    /// partial block is carried across the segment boundary so the 16-byte
    /// block alignment of the concatenated message is preserved.
    ///
    /// The arithmetic is the poly1305-donna design used by NaCl, BouncyCastle
    /// and OpenSSH: h lives in five 26-bit limbs inside ulong accumulators,
    /// and each multiply-reduce step is five dot products of at most
    /// ~5 * 2^26 * 2^28.4 ~ 2^58, so the 64-bit arithmetic never wraps and no
    /// arbitrary-precision (BigInteger) math is needed.
    /// </summary>
    private static void Poly1305(ReadOnlySpan<byte> key, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> tag)
    {
        var r0 = Load32(key, 0) & 0x3ffffff;
        var r1 = (Load32(key, 3) >> 2) & 0x3ffff03;
        var r2 = (Load32(key, 6) >> 4) & 0x3ffc0ff;
        var r3 = (Load32(key, 9) >> 6) & 0x3f03fff;
        var r4 = (Load32(key, 12) >> 8) & 0x00fffff;
        var s1 = r1 * 5; var s2 = r2 * 5; var s3 = r3 * 5; var s4 = r4 * 5;

        ulong h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
        Span<byte> leftover = stackalloc byte[16];
        var leftoverLen = 0;

        Accumulate(ref h0, ref h1, ref h2, ref h3, ref h4, r0, r1, r2, r3, r4, s1, s2, s3, s4, a, leftover, ref leftoverLen);
        Accumulate(ref h0, ref h1, ref h2, ref h3, ref h4, r0, r1, r2, r3, r4, s1, s2, s3, s4, b, leftover, ref leftoverLen);

        // Final short block (if any): pad with 0x01 then zeros - bit (8*len).
        if (leftoverLen > 0)
        {
            leftover[leftoverLen] = 1;
            leftover[(leftoverLen + 1)..].Clear();
            Poly1305Blocks(ref h0, ref h1, ref h2, ref h3, ref h4, r0, r1, r2, r3, r4, s1, s2, s3, s4, leftover, hibit: 0);
        }

        // Fully carry h (the block loop leaves up to 2^26 of slack in h1).
        h2 += h1 >> 26; h1 &= M26;
        h3 += h2 >> 26; h2 &= M26;
        h4 += h3 >> 26; h3 &= M26;
        h0 += 5 * (h4 >> 26); h4 &= M26;   // 2^130 == 5 (mod 2^130 - 5)
        h1 += h0 >> 26; h0 &= M26;

        // h + -p: adding 5 to h with 130-bit wraparound yields h - p when
        // h >= p and h + 5 otherwise; g4's borrow picks the right one.
        var g0 = h0 + 5;
        var g1 = h1 + (g0 >> 26); g0 &= M26;
        var g2 = h2 + (g1 >> 26); g1 &= M26;
        var g3 = h3 + (g2 >> 26); g2 &= M26;
        var g4 = h4 + (g3 >> 26) - (1UL << 26); g3 &= M26;

        var mask = (g4 >> 63) - 1;   // ulong wraparound: all-ones when no borrow
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h % 2^128, packed into four 32-bit words.
        var w0 = (uint)(h0 | (h1 << 26));
        var w1 = (uint)((h1 >> 6) | (h2 << 20));
        var w2 = (uint)((h2 >> 12) | (h3 << 14));
        var w3 = (uint)((h3 >> 18) | (h4 << 8));

        // mac = (h + s) % 2^128, s = key[16..32).
        var k0 = Load32(key, 16); var k1 = Load32(key, 20); var k2 = Load32(key, 24); var k3 = Load32(key, 28);
        var f = (ulong)w0 + k0; w0 = (uint)f; f >>= 32;
        f = (ulong)w1 + k1 + f; w1 = (uint)f; f >>= 32;
        f = (ulong)w2 + k2 + f; w2 = (uint)f; f >>= 32;
        f = (ulong)w3 + k3 + f; w3 = (uint)f;

        BinaryPrimitives.WriteUInt32LittleEndian(tag, w0);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[4..], w1);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[8..], w2);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[12..], w3);
    }

    /// <summary>
    /// Feed one message segment into the Poly1305 accumulator. Full 16-byte
    /// blocks go through the multiply-reduce directly; a partial tail is kept
    /// in <paramref name="leftover"/> so block alignment is preserved across
    /// the two segments.
    /// </summary>
    private static void Accumulate(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3, ref ulong h4,
        ulong r0, ulong r1, ulong r2, ulong r3, ulong r4, ulong s1, ulong s2, ulong s3, ulong s4,
        ReadOnlySpan<byte> msg, Span<byte> leftover, ref int leftoverLen)
    {
        var offset = 0;
        if (leftoverLen > 0)
        {
            var take = Math.Min(16 - leftoverLen, msg.Length);
            msg[..take].CopyTo(leftover[leftoverLen..]);
            leftoverLen += take;
            offset += take;
            if (leftoverLen == 16)
            {
                Poly1305Blocks(ref h0, ref h1, ref h2, ref h3, ref h4, r0, r1, r2, r3, r4, s1, s2, s3, s4, leftover, hibit: 1UL << 24);
                leftoverLen = 0;
            }
            else
            {
                return; // the whole segment was absorbed into the pending block
            }
        }

        var fullBlocks = (msg.Length - offset) & ~15;
        if (fullBlocks > 0)
        {
            Poly1305Blocks(ref h0, ref h1, ref h2, ref h3, ref h4, r0, r1, r2, r3, r4, s1, s2, s3, s4, msg.Slice(offset, fullBlocks), hibit: 1UL << 24);
            offset += fullBlocks;
        }

        var tail = msg.Length - offset;
        if (tail > 0)
        {
            msg[offset..].CopyTo(leftover);
            leftoverLen = tail;
        }
    }

    /// <summary>
    /// Fold all full 16-byte blocks in <paramref name="msg"/> into h
    /// (appending the 0x01 byte via <paramref name="hibit"/>) and
    /// multiply-reduce by r mod 2^130 - 5. The dot products stay below 2^58,
    /// so the ulong arithmetic never wraps.
    /// </summary>
    private static void Poly1305Blocks(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3, ref ulong h4,
        ulong r0, ulong r1, ulong r2, ulong r3, ulong r4, ulong s1, ulong s2, ulong s3, ulong s4,
        ReadOnlySpan<byte> msg, ulong hibit)
    {
        var offset = 0;
        while (offset < msg.Length)
        {
            h0 += Load32(msg, offset) & 0x3ffffff;
            h1 += (Load32(msg, offset + 3) >> 2) & 0x3ffffff;
            h2 += (Load32(msg, offset + 6) >> 4) & 0x3ffffff;
            h3 += (Load32(msg, offset + 9) >> 6) & 0x3ffffff;
            h4 += (Load32(msg, offset + 12) >> 8) | hibit;

            var d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
            var d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
            var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
            var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
            var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

            // Partial h %= p with cumulative carries (donna-64 style): each
            // carry is folded into the next raw limb BEFORE its own carry is
            // extracted, so the crossing terms are never lost.
            var c = d0 >> 26; h0 = d0 & 0x3ffffff;
            d1 += c; c = d1 >> 26; h1 = d1 & 0x3ffffff;
            d2 += c; c = d2 >> 26; h2 = d2 & 0x3ffffff;
            d3 += c; c = d3 >> 26; h3 = d3 & 0x3ffffff;
            d4 += c; c = d4 >> 26; h4 = d4 & 0x3ffffff;
            h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
            h1 += c;

            offset += 16;
        }
    }

    private static uint Load32(ReadOnlySpan<byte> s, int offset)
        => BinaryPrimitives.ReadUInt32LittleEndian(s[offset..]);
}
