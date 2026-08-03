using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class CtrModeCryptoTransform : ICryptoTransform
    {
        private readonly SymmetricAlgorithm _algorithm;
        private readonly ICryptoTransform _transform;
        private readonly byte[] _iv;
        private readonly byte[] _block;

        // Reused keystream buffer. CTR is a stream cipher: the whole packet's
        // consecutive counter blocks are built in one shot and encrypted with
        // a single TransformBlock call, instead of one AES invocation per
        // 16-byte block (a 32KB SSH packet previously triggered ~2048
        // cascading managed-to-native AES calls). 64KB covers every SSH
        // packet (hard cap 35000 bytes) plus slack; a fallback path keeps the
        // original per-block semantics for larger inputs.
        private readonly byte[] _ks;


        public CtrModeCryptoTransform(SymmetricAlgorithm algorithm)
        {
            ArgumentNullException.ThrowIfNull(algorithm);

            algorithm.Mode = CipherMode.ECB;
            algorithm.Padding = PaddingMode.None;

            _algorithm = algorithm;
            _transform = algorithm.CreateEncryptor();
            _iv = algorithm.IV;
            _block = new byte[algorithm.BlockSize >> 3];
            _ks = new byte[1 << 16];
        }

        public bool CanReuseTransform
        {
            get { return true; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        public int InputBlockSize
        {
            get { return _algorithm.BlockSize; }
        }

        public int OutputBlockSize
        {
            get { return _algorithm.BlockSize; }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var bytesPerBlock = InputBlockSize >> 3;
            var blocks = (inputCount + bytesPerBlock - 1) / bytesPerBlock;
            var ksLen = blocks * bytesPerBlock;

            // Hot path: the whole packet fits the keystream buffer. Build all
            // consecutive counter blocks, encrypt them in one AES call, then
            // XOR in 8-byte (ulong) chunks. Mathematically identical to the
            // per-block loop — same keystream, same counter carry — so the
            // byte stream is unchanged.
            if (ksLen <= _ks.Length)
            {
                for (var b = 0; b < blocks; b++)
                {
                    Buffer.BlockCopy(_iv, 0, _ks, b * bytesPerBlock, bytesPerBlock);
                    var k = _iv.Length;
                    while (--k >= 0 && ++_iv[k] == 0) ;
                }

                // Single native AES-ECB invocation over all counter blocks.
                _transform.TransformBlock(_ks, 0, ksLen, _ks, 0);

                // XOR 8 bytes at a time, then the byte tail. Uses
                // ReadUnaligned/WriteUnaligned because the input/output spans
                // may not be 8-byte aligned (e.g. the ETM send path calls
                // Transform(..., offset 4, ...)); MemoryMarshal.Cast would
                // throw on a misaligned span. x64 unaligned ulong access is
                // as fast as aligned, so there is no throughput cost.
                ref var ksRef = ref MemoryMarshal.GetReference(_ks.AsSpan(0, ksLen));
                ref var srcRef = ref MemoryMarshal.GetReference(inputBuffer.AsSpan(inputOffset, inputCount));
                ref var dstRef = ref MemoryMarshal.GetReference(outputBuffer.AsSpan(outputOffset, inputCount));

                var i = 0;
                for (; i <= inputCount - sizeof(ulong); i += sizeof(ulong))
                {
                    var k = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref ksRef, i));
                    var s = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref srcRef, i));
                    Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, i), k ^ s);
                }
                for (; i < inputCount; i++)
                    Unsafe.Add(ref dstRef, i) = (byte)(Unsafe.Add(ref ksRef, i) ^ Unsafe.Add(ref srcRef, i));

                // Same return contract as the fallback: bytes processed, rounded
                // up to whole blocks.
                return ksLen;
            }

            // Fallback: input larger than the keystream buffer. Retain the
            // original per-block semantics and _iv advancement so the counter
            // state stays consistent across calls.
            var written = 0;
            for (var i = 0; i < inputCount; i += bytesPerBlock)
            {
                // CTR is a stream cipher: the final block may be shorter than
                // the cipher block size (e.g. ETM packets where packet_length
                // is not encrypted and the encrypted portion is not
                // block-aligned). Only consume the bytes actually present.
                var blockLen = Math.Min(bytesPerBlock, inputCount - i);

                written += _transform.TransformBlock(_iv, 0, bytesPerBlock, _block, 0);

                for (var j = 0; j < blockLen; j++)
                    outputBuffer[outputOffset + i + j] = (byte)(_block[j] ^ inputBuffer[inputOffset + i + j]);

                var k = _iv.Length;
                while (--k >= 0 && ++_iv[k] == 0) ;
            }

            return written;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var output = new byte[inputCount];
            TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
            return output;
        }

        public void Dispose()
        {
            _transform.Dispose();
        }
    }
}
