using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using FxSsh.Logging;

#nullable enable

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Built-in algorithm suites. The option lists (KeyExchangeAlgorithms,
    /// HostKeyAlgorithms, EncryptionAlgorithms, MacAlgorithms,
    /// CompressionAlgorithms) are the algorithms selectable on the current
    /// platform, in priority order; each catalog entry probes its own support
    /// once at static initialization. Assign a subset of a list to an
    /// AlgorithmSelection to limit a server to those algorithms; null means
    /// "all supported".
    /// </summary>
    public static class AlgorithmRegistry
    {
        // Field declaration order matters: the catalogs must be initialized
        // before the option lists, which are derived from them.

        private static readonly (string Name, Func<KexAlgorithm> Factory, bool Supported)[] KeyExchangeCatalog =
        [
            ("mlkem768x25519-sha256", () => new MlkemX25519Kex(), TryCreate(() => MLKem.GenerateKey(MLKemAlgorithm.MLKem768))),
            ("curve25519-sha256", () => new X25519Kex(), TryCreate(() => X25519DiffieHellman.GenerateKey())),
            ("ecdh-sha2-nistp256", () => new EcdhKex("nistp256"), TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))),
            ("ecdh-sha2-nistp384", () => new EcdhKex("nistp384"), TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384))),
            ("ecdh-sha2-nistp521", () => new EcdhKex("nistp521"), TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521))),
            ("diffie-hellman-group18-sha512", () => new DiffieHellmanKex(512, 8192), true),
            ("diffie-hellman-group16-sha512", () => new DiffieHellmanKex(512, 4096), true),
            ("diffie-hellman-group14-sha256", () => new DiffieHellmanKex(256, 2048), true),
        ];

        private static readonly (string Name, Func<string, PublicKeyAlgorithm> Factory, bool Supported)[] HostKeyCatalog =
        [
            ("ecdsa-sha2-nistp256", x => new EcdsaKey("nistp256", x), TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP256))),
            ("ecdsa-sha2-nistp384", x => new EcdsaKey("nistp384", x), TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP384))),
            ("ecdsa-sha2-nistp521", x => new EcdsaKey("nistp521", x), TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP521))),
            ("rsa-sha2-256", x => new RsaKey(256, x), TryCreate(() => RSA.Create())),
            ("rsa-sha2-512", x => new RsaKey(512, x), TryCreate(() => RSA.Create())),
        ];

        private static readonly (string Name, Func<CipherInfo> Factory, bool Supported)[] EncryptionCatalog =
        [
            ("aes256-ctr", () => new CipherInfo(Aes.Create(), 256, CipherModeEx.CTR), TryCreate(() => Aes.Create())),
            ("aes256-gcm@openssh.com", () => new CipherInfo(256), AesGcm.IsSupported),
            ("aes128-gcm@openssh.com", () => new CipherInfo(128), AesGcm.IsSupported),
        ];

        private static readonly (string Name, Func<HmacInfo> Factory, bool Supported)[] MacCatalog =
        [
            ("hmac-sha2-256", () => new HmacInfo(new HMACSHA256(), 256), true),
            ("hmac-sha2-512", () => new HmacInfo(new HMACSHA512(), 512), true),
            ("hmac-sha2-256-etm@openssh.com", () => new HmacInfo(new HMACSHA256(), 256, true), true),
            ("hmac-sha2-512-etm@openssh.com", () => new HmacInfo(new HMACSHA512(), 512, true), true),
        ];

        private static readonly (string Name, Func<CompressionAlgorithm> Factory, bool Supported)[] CompressionCatalog =
        [
            ("none", () => new NoCompression(), true),
        ];

        // --- Selectable option lists (filtered to what this platform supports) ---

        /// <summary>Key exchange algorithms selectable on this platform, in priority order.</summary>
        public static readonly IReadOnlyList<string> KeyExchangeAlgorithms = SupportedNames(KeyExchangeCatalog);

        /// <summary>Host key / signature algorithms selectable on this platform, in priority order.</summary>
        public static readonly IReadOnlyList<string> HostKeyAlgorithms = SupportedNames(HostKeyCatalog);

        /// <summary>Encryption (cipher) algorithms selectable on this platform, in priority order.</summary>
        public static readonly IReadOnlyList<string> EncryptionAlgorithms = SupportedNames(EncryptionCatalog);

        /// <summary>MAC algorithms selectable on this platform, in priority order.</summary>
        public static readonly IReadOnlyList<string> MacAlgorithms = SupportedNames(MacCatalog);

        /// <summary>Compression algorithms selectable on this platform, in priority order.</summary>
        public static readonly IReadOnlyList<string> CompressionAlgorithms = SupportedNames(CompressionCatalog);

        // --- Resolution: null selector = all supported, list = subset by name ---

        internal static Dictionary<string, Func<KexAlgorithm>> ResolveKeyExchange(IReadOnlyList<string>? selected)
            => Resolve(KeyExchangeCatalog, selected, "key exchange");

        internal static Dictionary<string, Func<string, PublicKeyAlgorithm>> ResolveHostKey(IReadOnlyList<string>? selected)
            => Resolve(HostKeyCatalog, selected, "host key");

        internal static Dictionary<string, Func<CipherInfo>> ResolveEncryption(IReadOnlyList<string>? selected)
            => Resolve(EncryptionCatalog, selected, "encryption");

        internal static Dictionary<string, Func<HmacInfo>> ResolveMac(IReadOnlyList<string>? selected)
            => Resolve(MacCatalog, selected, "MAC");

        internal static Dictionary<string, Func<CompressionAlgorithm>> ResolveCompression(IReadOnlyList<string>? selected)
            => Resolve(CompressionCatalog, selected, "compression");

        // Selects the catalog entries for the given names (or every supported
        // algorithm when no selector is set), skips unknown and unsupported
        // names with a warning, and throws when nothing is left.
        private static Dictionary<string, TValue> Resolve<TValue>(
            (string Name, TValue Factory, bool Supported)[] catalog,
            IReadOnlyList<string>? selected,
            string category)
        {
            var result = new Dictionary<string, TValue>();

            if (selected == null)
            {
                foreach (var entry in catalog)
                    if (entry.Supported)
                        result[entry.Name] = entry.Factory;
            }
            else
            {
                foreach (var name in selected)
                {
                    var entry = Array.Find(catalog, e => e.Name == name);
                    if (entry.Name == null)
                    {
                        Log.Warn($"Unknown {category} algorithm '{name}' - skipped.");
                        continue;
                    }
                    if (!entry.Supported)
                    {
                        Log.Warn($"{category} algorithm '{entry.Name}' is not supported on this platform - skipped.");
                        continue;
                    }
                    result[name] = entry.Factory;
                }
            }

            if (result.Count == 0)
                throw new InvalidOperationException($"No supported {category} algorithms configured.");

            return result;
        }

        private static IReadOnlyList<string> SupportedNames<TValue>((string Name, TValue Factory, bool Supported)[] catalog)
            => catalog.Where(e => e.Supported).Select(e => e.Name).ToArray();

        private static bool TryCreate(Func<IDisposable> create)
        {
            try
            {
                using var _ = create();
                return true;
            }
            catch (Exception ex) when (ex is PlatformNotSupportedException or CryptographicException)
            {
                return false;
            }
        }
    }

    /// <summary>
    /// A named set of algorithms that can only be mutated through
    /// <see cref="AlgorithmSelection.ConfigureHazmat"/>. Enumerating it yields
    /// each entry's (name, factory) in server preference order; the underlying
    /// dictionary type is never exposed.
    /// </summary>
    public interface IHazmatCollection<T> : IEnumerable<KeyValuePair<string, T>>
    {
        /// <summary>Register or replace an algorithm factory under a name.</summary>
        void Add(string name, T factory);

        /// <summary>Remove an algorithm by name; returns false if it was absent.</summary>
        bool Remove(string name);

        /// <summary>True if an algorithm is registered under the name.</summary>
        bool Contains(string name);

        /// <summary>Number of registered algorithms.</summary>
        int Count { get; }
    }

    /// <summary>
    /// Mutable view of the server's algorithm registry, handed only to
    /// <see cref="AlgorithmSelection.ConfigureHazmat"/>. Consumers use Add
    /// (register/replace) or Remove by name to plug in algorithms - a
    /// deliberately dangerous ("HazMat") operation that is the only way the
    /// registry may be changed after construction.
    /// </summary>
    public sealed class AlgorithmCatalog
    {
        internal AlgorithmCatalog(
            IHazmatCollection<Func<KexAlgorithm>> keyExchange,
            IHazmatCollection<Func<string, PublicKeyAlgorithm>> publicKey,
            IHazmatCollection<Func<CipherInfo>> encryption,
            IHazmatCollection<Func<HmacInfo>> hmac,
            IHazmatCollection<Func<CompressionAlgorithm>> compression)
        {
            KeyExchange = keyExchange;
            PublicKey = publicKey;
            Encryption = encryption;
            Hmac = hmac;
            Compression = compression;
        }

        /// <summary>Key exchange algorithms, in server preference order.</summary>
        public IHazmatCollection<Func<KexAlgorithm>> KeyExchange { get; }

        /// <summary>Host key / signature algorithms, in server preference order.</summary>
        public IHazmatCollection<Func<string, PublicKeyAlgorithm>> PublicKey { get; }

        /// <summary>Encryption (cipher) algorithms, in server preference order.</summary>
        public IHazmatCollection<Func<CipherInfo>> Encryption { get; }

        /// <summary>MAC algorithms, in server preference order.</summary>
        public IHazmatCollection<Func<HmacInfo>> Hmac { get; }

        /// <summary>Compression algorithms, in server preference order.</summary>
        public IHazmatCollection<Func<CompressionAlgorithm>> Compression { get; }
    }

    /// <summary>
    /// Per-server algorithm registry, seeded with every algorithm supported on
    /// this platform (matching upstream's null-selector default). The registry
    /// is read-only to consumers - it may only be changed through
    /// <see cref="ConfigureHazmat"/>, which hands a mutable
    /// <see cref="AlgorithmCatalog"/> to a callback. Insertion order is the
    /// server's preference order when it advertises its KEXINIT name-lists.
    /// </summary>
    public sealed class AlgorithmSelection
    {
        private sealed class AlgorithmCollection<T> : IHazmatCollection<T>
        {
            private readonly OrderedDictionary<string, T> _items;

            public AlgorithmCollection(IEnumerable<KeyValuePair<string, T>> seed)
            {
                _items = new OrderedDictionary<string, T>();
                foreach (var kv in seed)
                    _items[kv.Key] = kv.Value;
            }

            public void Add(string name, T factory) => _items[name] = factory;
            public bool Remove(string name) => _items.Remove(name);
            public bool Contains(string name) => _items.ContainsKey(name);
            public int Count => _items.Count;

            public IEnumerator<KeyValuePair<string, T>> GetEnumerator() =>
                ((IEnumerable<KeyValuePair<string, T>>)_items).GetEnumerator();

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        }

        private readonly AlgorithmCollection<Func<KexAlgorithm>> _keyExchange;
        private readonly AlgorithmCollection<Func<string, PublicKeyAlgorithm>> _publicKey;
        private readonly AlgorithmCollection<Func<CipherInfo>> _encryption;
        private readonly AlgorithmCollection<Func<HmacInfo>> _hmac;
        private readonly AlgorithmCollection<Func<CompressionAlgorithm>> _compression;

        public AlgorithmSelection()
        {
            // Null selectors resolve to every algorithm supported on this
            // platform, matching upstream's default.
            _keyExchange = new AlgorithmCollection<Func<KexAlgorithm>>(AlgorithmRegistry.ResolveKeyExchange(null));
            _publicKey = new AlgorithmCollection<Func<string, PublicKeyAlgorithm>>(AlgorithmRegistry.ResolveHostKey(null));
            _encryption = new AlgorithmCollection<Func<CipherInfo>>(AlgorithmRegistry.ResolveEncryption(null));
            _hmac = new AlgorithmCollection<Func<HmacInfo>>(AlgorithmRegistry.ResolveMac(null));
            _compression = new AlgorithmCollection<Func<CompressionAlgorithm>>(AlgorithmRegistry.ResolveCompression(null));
        }

        /// <summary>
        /// The only way to change the algorithm registry. The callback receives
        /// a mutable <see cref="AlgorithmCatalog"/> whose per-category
        /// collections may be added to or removed from; outside this method the
        /// registry is read-only. Named "HazMat" to signal that mutating the
        /// advertised algorithm set is an expert-only operation.
        /// </summary>
        public void ConfigureHazmat(Action<AlgorithmCatalog> configure)
        {
            ArgumentNullException.ThrowIfNull(configure);
            configure(new AlgorithmCatalog(_keyExchange, _publicKey, _encryption, _hmac, _compression));
        }

        // Read access for the library internals (Session / SshServer). These are
        // deliberately not public - consumers see only ConfigureHazmat.
        internal IEnumerable<KeyValuePair<string, Func<KexAlgorithm>>> KeyExchange => _keyExchange;
        internal IEnumerable<KeyValuePair<string, Func<string, PublicKeyAlgorithm>>> PublicKey => _publicKey;
        internal IEnumerable<KeyValuePair<string, Func<CipherInfo>>> Encryption => _encryption;
        internal IEnumerable<KeyValuePair<string, Func<HmacInfo>>> Hmac => _hmac;
        internal IEnumerable<KeyValuePair<string, Func<CompressionAlgorithm>>> Compression => _compression;
    }
}
