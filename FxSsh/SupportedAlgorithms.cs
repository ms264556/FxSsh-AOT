using System;
using System.Collections.Generic;
using FxSsh.Algorithms;

namespace FxSsh
{
    /// <summary>
    /// Pluggable algorithm registry for the SSH algorithms the server may
    /// negotiate (RFC 4253 section 7.1). Each category is an
    /// <see cref="OrderedDictionary{TKey,TValue}"/> so that insertion order IS
    /// the server's preference order when it advertises its KEXINIT name-lists.
    /// The dictionaries are seeded with the built-in defaults from
    /// <see cref="AlgorithmRegistry"/> and are mutable within the assembly.
    /// Session uses this table as its authoritative resolution source. The
    /// public configuration surface is <see cref="HazMat"/>, obtained via
    /// <see cref="SshServer.HazMat"/>; it exposes the same collections, so a
    /// mutation (Add, Remove or override) is reflected in the negotiated set.
    /// </summary>
    internal class SupportedAlgorithms
    {
        public readonly OrderedDictionary<string, Func<KexAlgorithm>> KeyExchange = new();

        public readonly OrderedDictionary<string, Func<string, PublicKeyAlgorithm>> PublicKey = new();

        public readonly OrderedDictionary<string, Func<CipherInfo>> Encryption = new();

        public readonly OrderedDictionary<string, Func<HmacInfo>> Hmac = new();

        public readonly OrderedDictionary<string, Func<CompressionAlgorithm>> Compression = new();

        public SupportedAlgorithms()
        {
            // Seed from the built-in defaults (AlgorithmRegistry), preserving
            // their preference order, so Add/Remove/override behave like the
            // original SupportedAlgorithms.
            foreach (var kv in AlgorithmRegistry.ResolveKeyExchange(null)) KeyExchange[kv.Key] = kv.Value;
            foreach (var kv in AlgorithmRegistry.ResolveHostKey(null)) PublicKey[kv.Key] = kv.Value;
            foreach (var kv in AlgorithmRegistry.ResolveEncryption(null)) Encryption[kv.Key] = kv.Value;
            foreach (var kv in AlgorithmRegistry.ResolveMac(null)) Hmac[kv.Key] = kv.Value;
            foreach (var kv in AlgorithmRegistry.ResolveCompression(null)) Compression[kv.Key] = kv.Value;
        }
    }
}
