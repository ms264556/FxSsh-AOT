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
    /// Per-server algorithm selection. Each selector is null by default,
    /// meaning "use every algorithm in the corresponding AlgorithmRegistry
    /// option list"; assign a subset of the list to restrict that category.
    /// </summary>
    public sealed class AlgorithmSelection
    {
        /// <summary>Key exchange selector; null = all supported defaults.</summary>
        public IReadOnlyList<string>? KeyExchangeAlgorithms { get; set; }

        /// <summary>Host key selector; null = all supported defaults.</summary>
        public IReadOnlyList<string>? HostKeyAlgorithms { get; set; }

        /// <summary>Encryption (cipher) selector; null = all supported defaults.</summary>
        public IReadOnlyList<string>? EncryptionAlgorithms { get; set; }

        /// <summary>MAC selector; null = all supported defaults.</summary>
        public IReadOnlyList<string>? MacAlgorithms { get; set; }

        /// <summary>Compression selector; null = all supported defaults.</summary>
        public IReadOnlyList<string>? CompressionAlgorithms { get; set; }
    }
}
