using System;

namespace FxSsh.Algorithms
{
    public abstract class CompressionAlgorithm
    {
        /// <summary>
        /// True when Compress/Decompress are identity transforms (the negotiated
        /// "none" algorithm). Callers can use this to skip the intermediate
        /// payload byte[] entirely on the wire hot path.
        /// </summary>
        public virtual bool IsIdentity => false;

        public abstract byte[] Compress(byte[] input);

        public abstract ReadOnlyMemory<byte> Decompress(ReadOnlyMemory<byte> input);
    }
}
