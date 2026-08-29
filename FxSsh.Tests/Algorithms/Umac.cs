using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace FxSsh.Tests.Algorithms;

/// <summary>
/// <c>umac-64@openssh.com</c> and <c>umac-128@openssh.com</c> MAC algorithms.
/// <para>Ported from <see href="https://fastcrypto.org/umac/">umac.c</see> (Ted Krovetz, permissive license).</para>
/// </summary>
public sealed class Umac
{
    private const int KeyBytes = 16;
    private const int L1KeyLen = 1024;            // NH key length (bytes)
    private const int L1KeyShift = 16;            // Toeplitz key shift between streams
    private const int L1PadBoundary = 32;
    private const int HashBufBytes = 64;
    private const ulong P36 = 0x0000000FFFFFFFFB; // 2^36 - 5
    private const ulong P64 = 0xFFFFFFFFFFFFFFC5; // 2^64 - 59
    private const ulong M36 = 0x0000000FFFFFFFFF; // low 36 bits

    private readonly int _streams;                // tagBytes / 4: 2 (umac-64) or 4 (umac-128)
    private readonly Aes _pdfAes;                 // PDF AES-128 (ECB, no padding)
    private readonly byte[] _pdfNonce = new byte[16]; // cached masked nonce (first 8 bytes used)
    private readonly byte[] _pdfCache = new byte[16]; // AES(_pdfNonce)

    // NH streaming state (reset per message).
    private readonly byte[] _data = new byte[HashBufBytes];
    private uint _bytesHashed;
    private int _nextDataEmpty;
    private readonly ulong[] _state = new ulong[4];

    // Per-message uhash state.
    private readonly ulong[] _polyAccum = new ulong[4];
    private readonly ulong[] _nhResult = new ulong[4];
    private uint _msgLen;

    // Message cursors for the two-segment (a || b) input.
    private int _aPos;
    private int _bPos;

    public int TagBytes { get; }

    // RFC 4418 appendix lists the intermediate subkeys for the
    // 64-bit tag, so the derivation can be pinned exactly.
    private readonly uint[] _nhKey;
    private readonly ulong[] _polyKey;
    private readonly ulong[] _ipKeys;
    private readonly uint[] _ipTrans;

    public Umac(byte[] key, int tagBytes)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != KeyBytes)
            throw new ArgumentException("UMAC requires a 16-byte key.", nameof(key));
        if (tagBytes != 8 && tagBytes != 16)
            throw new ArgumentOutOfRangeException(nameof(tagBytes), tagBytes, "UMAC tag must be 8 or 16 bytes.");

        TagBytes = tagBytes;
        _streams = tagBytes / 4;

        // PRF key: AES-128 over the external key (umac.c aes_key_setup).
        using (var prf = CreateAes(key))
        {
            // kdf(ndx=0): the PDF's own AES key.
            var pdfKey = Kdf(prf, 0, KeyBytes);
            _pdfAes = CreateAes(pdfKey);

            // kdf(ndx=1): NH keys. On little-endian hosts umac.c endian-converts
            // each 4-byte word, i.e. every word is the big-endian interpretation
            // of the kdf output bytes.
            var nhBytes = Kdf(prf, 1, L1KeyLen + L1KeyShift * (_streams - 1));
            _nhKey = new uint[nhBytes.Length / 4];
            for (var i = 0; i < _nhKey.Length; i++)
                _nhKey[i] = BinaryPrimitives.ReadUInt32BigEndian(nhBytes.AsSpan(i * 4));

            // kdf(ndx=2): poly64 keys - one 8-byte key per stream read at a
            // 24-byte stride, big-endian, then masked to the special domain.
            var buf = Kdf(prf, 2, (8 * _streams + 4) * 8);
            _polyKey = new ulong[_streams];
            for (var i = 0; i < _streams; i++)
                _polyKey[i] = BinaryPrimitives.ReadUInt64BigEndian(buf.AsSpan(24 * i, 8))
                    & 0x01FFFFFF01FFFFFFUL;

            // kdf(ndx=3): inner-product keys - 4 u64s per stream from
            // buf + (8*i+4)*8, big-endian, reduced into Z_p36. NOTE: a fresh
            // kdf(3) buffer, NOT the kdf(2) buffer used for the poly keys.
            var ipBuf = Kdf(prf, 3, (8 * _streams + 4) * 8);
            _ipKeys = new ulong[_streams * 4];
            for (var i = 0; i < _streams; i++)
                for (var j = 0; j < 4; j++)
                    _ipKeys[i * 4 + j] = BinaryPrimitives.ReadUInt64BigEndian(ipBuf.AsSpan((8 * i + 4) * 8 + j * 8)) % P36;

            // kdf(ndx=4): inner-product translations, big-endian u32s.
            var trans = Kdf(prf, 4, _streams * 4);
            _ipTrans = new uint[_streams];
            for (var i = 0; i < _streams; i++)
                _ipTrans[i] = BinaryPrimitives.ReadUInt32BigEndian(trans.AsSpan(i * 4));
        }

        // PDF state: nonce 0, cache = AES(0) (umac.c pdf_init).
        EncryptPdf();
    }

    private static Aes CreateAes(byte[] key)
    {
        var aes = Aes.Create();
        aes.KeySize = 128;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        return aes;
    }

    /// <summary>umac.c kdf: AES counter mode; in_buf[7] = ndx, in_buf[15] = counter (from 1).</summary>
    private static byte[] Kdf(Aes aes, byte ndx, int nbytes)
    {
        var output = new byte[nbytes];
        Span<byte> inBuf = stackalloc byte[16];
        inBuf.Clear();
        inBuf[7] = ndx;
        inBuf[15] = 1;
        Span<byte> block = stackalloc byte[16];
        var pos = 0;
        while (nbytes >= 16)
        {
            aes.EncryptEcb(inBuf, block, PaddingMode.None);
            block.CopyTo(output.AsSpan(pos));
            pos += 16;
            nbytes -= 16;
            inBuf[15] = (byte)(inBuf[15] + 1);
        }
        if (nbytes > 0)
        {
            aes.EncryptEcb(inBuf, block, PaddingMode.None);
            block[..nbytes].CopyTo(output.AsSpan(pos));
        }
        return output;
    }

    /// <summary>umac.c nh_update: incorporate bytes, buffering what is not a multiple of 64.</summary>
    private void NhUpdate(ReadOnlySpan<byte> buf)
    {
        var j = _nextDataEmpty;
        var nbytes = buf.Length;
        if (j + nbytes >= HashBufBytes)
        {
            if (j > 0)
            {
                var i = HashBufBytes - j;
                buf[..i].CopyTo(_data.AsSpan(j, i));
                NhTransform(_data, HashBufBytes);
                nbytes -= i;
                buf = buf[i..];
                _bytesHashed += HashBufBytes;
            }
            if (nbytes >= HashBufBytes)
            {
                var i = nbytes & ~(HashBufBytes - 1);
                NhTransform(buf[..i]);
                nbytes -= i;
                buf = buf[i..];
                _bytesHashed += (uint)i;
            }
            j = 0;
        }
        buf[..nbytes].CopyTo(_data.AsSpan(j, nbytes));
        _nextDataEmpty = j + nbytes;
    }

    private void NhTransform(ReadOnlySpan<byte> buf, int nbytes)
    {
        // The NH key is offset by the bytes hashed so far (umac.c nh_transform).
        var keyIndex = (int)(_bytesHashed >> 2);
        NhAux(keyIndex, buf, nbytes);
    }

    private void NhTransform(ReadOnlySpan<byte> buf)
        => NhTransform(buf, buf.Length);

    /// <summary>umac.c nh_aux for UMAC_OUTPUT_LEN 8 (two streams) and 16 (four streams).</summary>
    private void NhAux(int keyIndex, ReadOnlySpan<byte> d, int dlen)
    {
        var pos = 0;
        var c = dlen / 32;
        if (_streams == 2)
        {
            var h1 = _state[0];
            var h2 = _state[1];
            while (c-- > 0)
            {
                var k0 = _nhKey[keyIndex];
                var k1 = _nhKey[keyIndex + 1];
                var k2 = _nhKey[keyIndex + 2];
                var k3 = _nhKey[keyIndex + 3];
                var k4 = _nhKey[keyIndex + 4];
                var k5 = _nhKey[keyIndex + 5];
                var k6 = _nhKey[keyIndex + 6];
                var k7 = _nhKey[keyIndex + 7];
                var k8 = _nhKey[keyIndex + 8];
                var k9 = _nhKey[keyIndex + 9];
                var k10 = _nhKey[keyIndex + 10];
                var k11 = _nhKey[keyIndex + 11];

                var d0 = BinaryPrimitives.ReadUInt32LittleEndian(d[pos..]);
                var d1 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 4)..]);
                var d2 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 8)..]);
                var d3 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 12)..]);
                var d4 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 16)..]);
                var d5 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 20)..]);
                var d6 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 24)..]);
                var d7 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 28)..]);

                h1 += Mul64(k0 + d0, k4 + d4);
                h2 += Mul64(k4 + d0, k8 + d4);
                h1 += Mul64(k1 + d1, k5 + d5);
                h2 += Mul64(k5 + d1, k9 + d5);
                h1 += Mul64(k2 + d2, k6 + d6);
                h2 += Mul64(k6 + d2, k10 + d6);
                h1 += Mul64(k3 + d3, k7 + d7);
                h2 += Mul64(k7 + d3, k11 + d7);

                keyIndex += 8;
                pos += 32;
            }
            _state[0] = h1;
            _state[1] = h2;
        }
        else
        {
            var h1 = _state[0];
            var h2 = _state[1];
            var h3 = _state[2];
            var h4 = _state[3];
            while (c-- > 0)
            {
                var k0 = _nhKey[keyIndex];
                var k1 = _nhKey[keyIndex + 1];
                var k2 = _nhKey[keyIndex + 2];
                var k3 = _nhKey[keyIndex + 3];
                var k4 = _nhKey[keyIndex + 4];
                var k5 = _nhKey[keyIndex + 5];
                var k6 = _nhKey[keyIndex + 6];
                var k7 = _nhKey[keyIndex + 7];
                var k8 = _nhKey[keyIndex + 8];
                var k9 = _nhKey[keyIndex + 9];
                var k10 = _nhKey[keyIndex + 10];
                var k11 = _nhKey[keyIndex + 11];
                var k12 = _nhKey[keyIndex + 12];
                var k13 = _nhKey[keyIndex + 13];
                var k14 = _nhKey[keyIndex + 14];
                var k15 = _nhKey[keyIndex + 15];
                var k16 = _nhKey[keyIndex + 16];
                var k17 = _nhKey[keyIndex + 17];
                var k18 = _nhKey[keyIndex + 18];
                var k19 = _nhKey[keyIndex + 19];

                var d0 = BinaryPrimitives.ReadUInt32LittleEndian(d[pos..]);
                var d1 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 4)..]);
                var d2 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 8)..]);
                var d3 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 12)..]);
                var d4 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 16)..]);
                var d5 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 20)..]);
                var d6 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 24)..]);
                var d7 = BinaryPrimitives.ReadUInt32LittleEndian(d[(pos + 28)..]);

                h1 += Mul64(k0 + d0, k4 + d4);
                h2 += Mul64(k4 + d0, k8 + d4);
                h3 += Mul64(k8 + d0, k12 + d4);
                h4 += Mul64(k12 + d0, k16 + d4);
                h1 += Mul64(k1 + d1, k5 + d5);
                h2 += Mul64(k5 + d1, k9 + d5);
                h3 += Mul64(k9 + d1, k13 + d5);
                h4 += Mul64(k13 + d1, k17 + d5);
                h1 += Mul64(k2 + d2, k6 + d6);
                h2 += Mul64(k6 + d2, k10 + d6);
                h3 += Mul64(k10 + d2, k14 + d6);
                h4 += Mul64(k14 + d2, k18 + d6);
                h1 += Mul64(k3 + d3, k7 + d7);
                h2 += Mul64(k7 + d3, k11 + d7);
                h3 += Mul64(k11 + d3, k15 + d7);
                h4 += Mul64(k15 + d3, k19 + d7);

                keyIndex += 8;
                pos += 32;
            }
            _state[0] = h1;
            _state[1] = h2;
            _state[2] = h3;
            _state[3] = h4;
        }
    }

    /// <summary>umac.c nh_final: pad the buffer, fold in the bit length, reset.</summary>
    private void NhFinal(ulong[] result)
    {
        if (_nextDataEmpty != 0)
        {
            var nhLen = (_nextDataEmpty + (L1PadBoundary - 1)) & ~(L1PadBoundary - 1);
            _data.AsSpan(_nextDataEmpty, nhLen - _nextDataEmpty).Clear();
            NhTransform(_data, nhLen);
            _bytesHashed += (uint)_nextDataEmpty;
        }
        else if (_bytesHashed == 0)
        {
            _data.AsSpan(0, L1PadBoundary).Clear();
            NhTransform(_data, L1PadBoundary);
        }

        var nbits = (ulong)_bytesHashed << 3;
        for (var i = 0; i < _streams; i++)
            result[i] = _state[i] + nbits;
        NhReset();
    }

    private void NhReset()
    {
        _bytesHashed = 0;
        _nextDataEmpty = 0;
        _state[0] = 0;
        _state[1] = 0;
        _state[2] = 0;
        _state[3] = 0;
    }

    private static ulong Mul64(uint a, uint b) => a * (ulong)b;

    /// <summary>umac.c poly_hash: fold each NH output stream through poly64.</summary>
    private void PolyHash(ulong[] data)
    {
        for (var i = 0; i < _streams; i++)
        {
            if ((uint)(data[i] >> 32) == 0xFFFFFFFF)
            {
                _polyAccum[i] = Poly64(_polyAccum[i], _polyKey[i], P64 - 1);
                _polyAccum[i] = Poly64(_polyAccum[i], _polyKey[i], data[i] - 59);
            }
            else
            {
                _polyAccum[i] = Poly64(_polyAccum[i], _polyKey[i], data[i]);
            }
        }
    }

    /// <summary>umac.c poly64: Horner's rule over Z_p64 with 32-bit half-products.</summary>
    private static ulong Poly64(ulong cur, ulong key, ulong data)
    {
        var keyHi = (uint)(key >> 32);
        var keyLo = (uint)key;
        var curHi = (uint)(cur >> 32);
        var curLo = (uint)cur;

        var x = Mul64(keyHi, curLo) + Mul64(curHi, keyLo);
        var xLo = (uint)x;
        var xHi = (uint)(x >> 32);

        var res = (Mul64(keyHi, curHi) + xHi) * 59 + Mul64(keyLo, curLo);

        var t = (ulong)xLo << 32;
        res += t;
        if (res < t) res += 59;

        res += data;
        if (res < data) res += 59;

        return res;
    }

    /// <summary>umac.c ip_aux: inner-product of a 64-bit value with four 36-bit keys.</summary>
    private static ulong IpAux(ulong t, ulong[] keys, int offset, ulong data)
    {
        t += keys[offset] * (ushort)(data >> 48);
        t += keys[offset + 1] * (ushort)(data >> 32);
        t += keys[offset + 2] * (ushort)(data >> 16);
        t += keys[offset + 3] * (ushort)data;
        return t;
    }

    /// <summary>umac.c ip_reduce_p36: divisionless modular reduction into Z_p36.</summary>
    private static uint IpReduceP36(ulong t)
    {
        var ret = (t & M36) + 5 * (t >> 36);
        if (ret >= P36) ret -= P36;
        return (uint)ret;
    }

    /// <summary>umac.c ip_short: inner-product hash applied directly to the NH output (short messages).</summary>
    private void IpShort(Span<byte> res)
    {
        for (var i = 0; i < _streams; i++)
        {
            var t = IpAux(0, _ipKeys, i * 4, _nhResult[i]);
            BinaryPrimitives.WriteUInt32BigEndian(res[(i * 4)..], IpReduceP36(t) ^ _ipTrans[i]);
        }
    }

    /// <summary>umac.c ip_long: inner-product hash applied to the polyhash output (long messages).</summary>
    private void IpLong(Span<byte> res)
    {
        for (var i = 0; i < _streams; i++)
        {
            if (_polyAccum[i] >= P64) _polyAccum[i] -= P64;
            var t = IpAux(0, _ipKeys, i * 4, _polyAccum[i]);
            BinaryPrimitives.WriteUInt32BigEndian(res[(i * 4)..], IpReduceP36(t) ^ _ipTrans[i]);
        }
    }

    /// <summary>
    /// Compute the SSH packet tag over the concatenation a || b (the same MAC
    /// input an HMAC would cover, minus the sequence number - OpenSSH mac.c
    /// hashes only the packet data) and write the first <see cref="TagBytes"/>
    /// bytes to <paramref name="destination"/>.
    /// </summary>
    public void Compute(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, uint sequence, Span<byte> destination)
    {
        // SSH nonce: the 8-byte big-endian packet sequence number (mac.c POKE_U64).
        Span<byte> nonce = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(nonce, sequence);
        ComputeCore(a, b, nonce, destination);
    }

    private void ComputeCore(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> nonce, Span<byte> destination)
    {
        if (destination.Length < TagBytes)
            throw new ArgumentException("Destination too short for UMAC tag.", nameof(destination));

        Span<byte> tag = stackalloc byte[32];
        ComputeUhashCore(a, b, tag);
        PdfGenXor(tag, nonce);
        tag[..TagBytes].CopyTo(destination);
    }

    private void ComputeUhashCore(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> tag)
    {
        // Per-message state reset (umac.c uhash_reset + nh_reset). The polyhash
        // prepends a non-zero word, so the accumulator starts at 1.
        _msgLen = 0;
        _aPos = 0;
        _bPos = 0;
        NhReset();
        for (var i = 0; i < _streams; i++) _polyAccum[i] = 1;

        var total = a.Length + b.Length;
        if (total <= L1KeyLen)
        {
            // Short path (umac.c uhash_update short branch + uhash_final): a
            // single NH pass, then the inner-product hash directly on its output.
            Feed(a, b, total);
            _msgLen = (uint)total;
            NhFinal(_nhResult);
            IpShort(tag);
            return;
        }

        // Long path: NH each full 1024-byte block, folding its output through
        // the polyhash; the trailing partial block stays in the NH buffer.
        var consumed = 0;
        while (total - consumed >= L1KeyLen)
        {
            Feed(a, b, L1KeyLen);
            _msgLen += L1KeyLen;
            NhFinal(_nhResult);
            PolyHash(_nhResult);
            consumed += L1KeyLen;
        }
        var tail = total - consumed;
        if (tail > 0)
        {
            Feed(a, b, tail);
            _msgLen += (uint)tail;
        }
        if (_msgLen % L1KeyLen != 0)
        {
            NhFinal(_nhResult);
            PolyHash(_nhResult);
        }
        IpLong(tag);
    }

    /// <summary>
    /// Feed <paramref name="count"/> bytes from the virtual a || b stream to
    /// the NH layer, transparently crossing the a/b boundary (umac.c uhash_update
    /// sees one contiguous message).
    /// </summary>
    private void Feed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, int count)
    {
        while (count > 0)
        {
            if (_aPos < a.Length)
            {
                var n = Math.Min(count, a.Length - _aPos);
                NhUpdate(a.Slice(_aPos, n));
                _aPos += n;
                count -= n;
            }
            else
            {
                var n = Math.Min(count, b.Length - _bPos);
                NhUpdate(b.Slice(_bPos, n));
                _bPos += n;
                count -= n;
            }
        }
    }

    /// <summary>umac.c pdf_gen_xor: XOR the uhash output with the AES PDF, keyed by the 8-byte nonce.</summary>
    private void PdfGenXor(Span<byte> tag, ReadOnlySpan<byte> nonce)
    {
        Span<byte> pad = stackalloc byte[16];
        ComputePdfPad(nonce, pad);
        if (TagBytes == 8)
        {
            var ndx = nonce[7] & 1;
            for (var i = 0; i < 8; i++)
                tag[i] ^= pad[ndx * 8 + i];
        }
        else
        {
            for (var i = 0; i < 16; i++)
                tag[i] ^= pad[i];
        }
    }

    private void ComputePdfPad(ReadOnlySpan<byte> nonce, Span<byte> pad)
    {
        // The C code masks a copy of the nonce's last byte (never the caller's
        // buffer); mirror that on a stack copy.
        Span<byte> masked = stackalloc byte[8];
        nonce.CopyTo(masked);
        if (TagBytes == 8) masked[7] &= 0xFE;

        if (!masked.SequenceEqual(_pdfNonce.AsSpan(0, 8)))
        {
            masked.CopyTo(_pdfNonce);
            _pdfNonce.AsSpan(8).Clear();
            EncryptPdf();
        }
        _pdfCache.CopyTo(pad);
    }

    private void EncryptPdf()
        => _pdfAes.EncryptEcb(_pdfNonce, _pdfCache, PaddingMode.None);
}
