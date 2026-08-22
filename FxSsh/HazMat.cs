using System;
using System.Collections.Generic;
using FxSsh.Algorithms;

namespace FxSsh
{
    /// <summary>
    /// Public configuration surface for the server's pluggable algorithm
    /// registry. Backed by the internal <see cref="SupportedAlgorithms"/>; the
    /// collections exposed here ARE the live registry, so Clear/Add/Remove/Insert
    /// on them is immediately reflected in the advertised KEXINIT name-lists on
    /// the next connection. Obtain via <see cref="SshServer.HazMat"/>.
    /// </summary>
    public sealed class HazMat
    {
        private readonly SupportedAlgorithms _supported;

        internal HazMat(SupportedAlgorithms supported) => _supported = supported;

        /// <summary>Key exchange algorithms (name -> factory), in server preference order.</summary>
        public OrderedDictionary<string, Func<KexAlgorithm>> KeyExchange => _supported.KeyExchange;

        /// <summary>Host key / signature algorithms (name -> factory built from key material).</summary>
        public OrderedDictionary<string, Func<string, PublicKeyAlgorithm>> PublicKey => _supported.PublicKey;

        /// <summary>Encryption (cipher) algorithms.</summary>
        public OrderedDictionary<string, Func<CipherInfo>> Encryption => _supported.Encryption;

        /// <summary>MAC algorithms.</summary>
        public OrderedDictionary<string, Func<HmacInfo>> Hmac => _supported.Hmac;

        /// <summary>Compression algorithms.</summary>
        public OrderedDictionary<string, Func<CompressionAlgorithm>> Compression => _supported.Compression;

        /// <summary>
        /// Idiomatic configuration hook: run <paramref name="configure"/> against
        /// this configuration so callers can fluently Clear/Add/Remove/Insert
        /// algorithms (for example to pin a hardened algorithm set) without
        /// touching the library.
        /// </summary>
        public void OverrideSafeAlgorithmDefaults(Action<HazMat> configure)
        {
            ArgumentNullException.ThrowIfNull(configure);
            configure(this);
        }
    }
}
