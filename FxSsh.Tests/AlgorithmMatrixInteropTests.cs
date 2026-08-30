using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FxSsh.Tests.Algorithms;
using Renci.SshNet;
using Xunit;
using Xunit.Sdk;
using CipherInfo = FxSsh.Algorithms.CipherInfo;
using CipherModeEx = FxSsh.Algorithms.CipherModeEx;
using HmacInfo = FxSsh.Algorithms.HmacInfo;

namespace FxSsh.Tests;

/// <summary>
/// The full algorithm matrix: EVERY algorithm the server can negotiate -
/// the built-in default set (FxSsh/Algorithms/AlgorithmRegistry.cs) plus every
/// pluggable algorithm in FxSsh.Tests/Algorithms - is exercised end-to-end
/// against BOTH real clients:
///
///  1. SSH.NET (in-process): the client's offer list is pruned down to the
///     single algorithm under test, so a successful handshake + data
///     round-trip proves that exact algorithm was negotiated and used.
///  2. OpenSSH (real ssh.exe process): the client's offer list is forced to
///     the single algorithm with -o KexAlgorithms= / HostKeyAlgorithms= /
///     Ciphers= / MACs= / Compression=, and the -vv log is asserted to show
///     it was actually negotiated, with an echo round-trip over the session.
///
/// Each row is skipped (with a reason shown in the results) when the client
/// does not ship the algorithm at all - e.g. SSH.NET ships no umac-* MAC,
/// and an older OpenSSH client may lack sntrup761 / mlkem768x25519. The
/// skips are computed from the real client's own algorithm tables (SSH.NET's
/// ConnectionInfo dictionaries, `ssh -Q` output), not from a hard-coded
/// list, so they stay correct as clients evolve.
/// </summary>
public class AlgorithmMatrixInteropTests
{
    public enum AlgoCategory
    {
        Kex,
        HostKey,
        Cipher,
        Mac,
        Compression
    }

    /// <summary>
    /// One algorithm row: how to force it on each client and what to assert.
    /// Implements <see cref="IXunitSerializable"/> (payload is enum / string /
    /// bool only), so the theory rows are individually identified by the test
    /// runner (xUnit1044/1046-compliant). Plugin registration lives in
    /// <see cref="PluginRegistrations"/>, keyed by the row's Name, so no
    /// delegate is stored in the row itself.
    /// </summary>
    public sealed record AlgoCase : IXunitSerializable
    {
        public AlgoCase(AlgoCategory category, string name, string? sshNetReported = null, bool allHostKeys = false)
        {
            Category = category;
            Name = name;
            SshNetReported = sshNetReported;
            AllHostKeys = allHostKeys;
        }

        // Public parameterless ctor required by xUnit for row deserialization (xUnit3001).
        public AlgoCase() : this(default, "") { }

        public AlgoCategory Category { get; private set; }
        public string Name { get; private set; }
        public string? SshNetReported { get; private set; }
        public bool AllHostKeys { get; private set; }

        public override string ToString() => Name;

        public void Serialize(IXunitSerializationInfo info)
        {
            info.AddValue(nameof(Category), Category);
            info.AddValue(nameof(Name), Name);
            info.AddValue(nameof(SshNetReported), SshNetReported);
            info.AddValue(nameof(AllHostKeys), AllHostKeys);
        }

        public void Deserialize(IXunitSerializationInfo info)
        {
            Category = info.GetValue<AlgoCategory>(nameof(Category));
            Name = info.GetValue<string>(nameof(Name)) ?? "";
            SshNetReported = info.GetValue<string>(nameof(SshNetReported));
            AllHostKeys = info.GetValue<bool>(nameof(AllHostKeys));
        }
    }

    // ------------------------------------------------------------------
    // The matrix. Built-in rows use the exact names from FxSsh's
    // AlgorithmSelection; plugin rows are registered on the server by name
    // through PluginRegistrations (see below).
    // ------------------------------------------------------------------

    private static readonly AlgoCase[] All =
    [
        // ---- key exchange: built-in ----
        new(AlgoCategory.Kex, "ecdh-sha2-nistp256"),
        new(AlgoCategory.Kex, "ecdh-sha2-nistp384"),
        new(AlgoCategory.Kex, "ecdh-sha2-nistp521"),
        new(AlgoCategory.Kex, "curve25519-sha256"),
        new(AlgoCategory.Kex, "diffie-hellman-group18-sha512"),
        new(AlgoCategory.Kex, "diffie-hellman-group16-sha512"),
        new(AlgoCategory.Kex, "diffie-hellman-group14-sha256"),

        // ---- key exchange: plugin ----
        new(AlgoCategory.Kex, "diffie-hellman-group14-sha1"),
        new(AlgoCategory.Kex, "sntrup761x25519-sha512@openssh.com", sshNetReported: "sntrup761x25519-sha512"),
        new(AlgoCategory.Kex, "sntrup761x25519-sha512"),
        new(AlgoCategory.Kex, "mlkem768x25519-sha256"),

        // ---- host key: built-in ----
        new(AlgoCategory.HostKey, "ecdsa-sha2-nistp256", allHostKeys: true),
        new(AlgoCategory.HostKey, "ecdsa-sha2-nistp384", allHostKeys: true),
        new(AlgoCategory.HostKey, "ecdsa-sha2-nistp521", allHostKeys: true),
        new(AlgoCategory.HostKey, "rsa-sha2-256", allHostKeys: true),
        new(AlgoCategory.HostKey, "rsa-sha2-512", allHostKeys: true),

        // ---- host key: plugin ----
        new(AlgoCategory.HostKey, "ssh-ed25519", allHostKeys: true),
        new(AlgoCategory.HostKey, "ssh-rsa", allHostKeys: true),

        // ---- cipher: built-in ----
        new(AlgoCategory.Cipher, "aes256-ctr"),
        new(AlgoCategory.Cipher, "aes256-gcm@openssh.com"),
        new(AlgoCategory.Cipher, "aes128-gcm@openssh.com"),

        // ---- cipher: plugin ----
        new(AlgoCategory.Cipher, "chacha20-poly1305@openssh.com"),
        new(AlgoCategory.Cipher, "aes128-ctr"),
        new(AlgoCategory.Cipher, "aes192-ctr"),

        // ---- MAC: built-in ----
        new(AlgoCategory.Mac, "hmac-sha2-256"),
        new(AlgoCategory.Mac, "hmac-sha2-512"),
        new(AlgoCategory.Mac, "hmac-sha2-256-etm@openssh.com"),
        new(AlgoCategory.Mac, "hmac-sha2-512-etm@openssh.com"),

        // ---- MAC: plugin ----
        new(AlgoCategory.Mac, "hmac-sha1"),
        new(AlgoCategory.Mac, "hmac-sha1-etm@openssh.com"),
        new(AlgoCategory.Mac, "umac-64@openssh.com"),
        new(AlgoCategory.Mac, "umac-64-etm@openssh.com"),
        new(AlgoCategory.Mac, "umac-128@openssh.com"),
        new(AlgoCategory.Mac, "umac-128-etm@openssh.com"),

        // ---- compression ----
        new(AlgoCategory.Compression, "none"),
    ];

    // ------------------------------------------------------------------
    // Plugin registration, keyed by the row's Name instead of a delegate in
    // the row itself (AlgoCase stays serializable - xUnit1044).
    // ------------------------------------------------------------------

    // The legacy rows below deliberately exercise the deprecated algorithms
    // (diffie-hellman-group14-sha1, ssh-rsa, umac-*) - interop with old
    // clients is exactly what they are for.
#pragma warning disable CS0618
    /// <summary>Register the plugin algorithm for a row on the server. Built-in rows have no entry.</summary>
    private static readonly Dictionary<string, Action<TestSshServer>> PluginRegistrations = new()
    {
        // ---- key exchange ----
        ["diffie-hellman-group14-sha1"] = s => s.Algorithms.ConfigureHazmat(c => c.KeyExchange.Add("diffie-hellman-group14-sha1", () => new LegacyDiffieHellmanKex())),
        ["sntrup761x25519-sha512@openssh.com"] = s => s.Algorithms.ConfigureHazmat(c => c.KeyExchange.Add("sntrup761x25519-sha512@openssh.com", () => new Sntrup761X25519Kex())),
        ["sntrup761x25519-sha512"] = s => s.Algorithms.ConfigureHazmat(c => c.KeyExchange.Add("sntrup761x25519-sha512", () => new Sntrup761X25519Kex())),
        ["mlkem768x25519-sha256"] = s => s.Algorithms.ConfigureHazmat(c => c.KeyExchange.Add("mlkem768x25519-sha256", () => new MlKem768X25519Kex())),

        // ---- host key ----
        ["ssh-ed25519"] = s =>
        {
            s.Algorithms.ConfigureHazmat(c => c.PublicKey.Add("ssh-ed25519", key => new Ed25519Key(key)));
            s.AddHostKey("ssh-ed25519", Ed25519Key.GenerateKeyPem());
        },
        ["ssh-rsa"] = s => s.Algorithms.ConfigureHazmat(c => c.PublicKey.Add("ssh-rsa", x => new LegacyRsaKey(x))),

        // ---- cipher ----
        ["chacha20-poly1305@openssh.com"] = s => s.Algorithms.ConfigureHazmat(c => c.Encryption.Add("chacha20-poly1305@openssh.com",
            () => new CipherInfo(key => new ChaCha20Poly1305Transform(key), keySize: 512, blockSizeBits: 64))),
        ["aes128-ctr"] = s => s.Algorithms.ConfigureHazmat(c => c.Encryption.Add("aes128-ctr", () => new CipherInfo(Aes.Create(), 128, CipherModeEx.CTR))),
        ["aes192-ctr"] = s => s.Algorithms.ConfigureHazmat(c => c.Encryption.Add("aes192-ctr", () => new CipherInfo(Aes.Create(), 192, CipherModeEx.CTR))),

        // ---- MAC ----
        ["hmac-sha1"] = s => s.Algorithms.ConfigureHazmat(c => c.Hmac.Add("hmac-sha1", () => new HmacInfo(new HMACSHA1(), 160))),
        ["hmac-sha1-etm@openssh.com"] = s => s.Algorithms.ConfigureHazmat(c => c.Hmac.Add("hmac-sha1-etm@openssh.com", () => new HmacInfo(new HMACSHA1(), 160, isEtm: true))),
        ["umac-64@openssh.com"] = s => s.Algorithms.ConfigureHazmat(c => c.Hmac.Add("umac-64@openssh.com",
            () => new HmacInfo(key => new UmacHmacAlgorithm(key, 8), keySize: 128, isEtm: false))),
        ["umac-64-etm@openssh.com"] = s => s.Algorithms.ConfigureHazmat(c => c.Hmac.Add("umac-64-etm@openssh.com",
            () => new HmacInfo(key => new UmacHmacAlgorithm(key, 8), keySize: 128, isEtm: true))),
        ["umac-128@openssh.com"] = s => s.Algorithms.ConfigureHazmat(c => c.Hmac.Add("umac-128@openssh.com",
            () => new HmacInfo(key => new UmacHmacAlgorithm(key, 16), keySize: 128, isEtm: false))),
        ["umac-128-etm@openssh.com"] = s => s.Algorithms.ConfigureHazmat(c => c.Hmac.Add("umac-128-etm@openssh.com",
            () => new HmacInfo(key => new UmacHmacAlgorithm(key, 16), keySize: 128, isEtm: true))),
    };
#pragma warning restore CS0618

    /// <summary>Apply the row's plugin registration (no-op for built-in algorithms).</summary>
    private static void RegisterPlugins(TestSshServer server, AlgoCase algo)
    {
        if (PluginRegistrations.TryGetValue(algo.Name, out var register))
            register(server);
    }

    // ------------------------------------------------------------------
    // Per-client row generation: skip (with reason) whatever the client
    // does not ship, so "only if the client supports this algorithm" is
    // data-driven from the client's own tables.
    // ------------------------------------------------------------------

    /// <summary>Rows for the SSH.NET leg, computed from SSH.NET's own algorithm dictionaries.</summary>
    public static TheoryData<AlgoCase> SshNetRows => BuildSshNetRows();

    /// <summary>Rows for the OpenSSH leg, computed from `ssh -Q` on the found client.</summary>
    public static TheoryData<AlgoCase> OpenSshRows => BuildOpenSshRows();

    private static TheoryData<AlgoCase> BuildSshNetRows()
    {
        var probe = AlgorithmInteropHelper.CreateConnectionInfo(1); // port is irrelevant for table probing
        var rows = new TheoryData<AlgoCase>();
        foreach (var algo in All)
        {
            if (!SshNetShips(probe, algo))
            {
                rows.Add(new TheoryDataRow<AlgoCase>(algo)
                    .WithSkip($"{algo.Name} is not shipped by SSH.NET"));
                continue;
            }

            rows.Add(algo);
        }

        return rows;
    }

    private static bool SshNetShips(ConnectionInfo probe, AlgoCase algo) => algo.Category switch
    {
        AlgoCategory.Kex => probe.KeyExchangeAlgorithms.ContainsKey(algo.Name),
        AlgoCategory.HostKey => probe.HostKeyAlgorithms.ContainsKey(algo.Name),
        AlgoCategory.Cipher => probe.Encryptions.ContainsKey(algo.Name),
        AlgoCategory.Mac => probe.HmacAlgorithms.ContainsKey(algo.Name),
        AlgoCategory.Compression => probe.CompressionAlgorithms.ContainsKey(algo.Name),
        _ => false
    };

    private static TheoryData<AlgoCase> BuildOpenSshRows()
    {
        var sshPath = FindSshExecutable();
        var rows = new TheoryData<AlgoCase>();
        foreach (var algo in All)
        {
            if (sshPath is null)
            {
                rows.Add(new TheoryDataRow<AlgoCase>(algo)
                    .WithSkip("OpenSSH client not installed - nothing to interop with."));
                continue;
            }

            if (!OpenSshShips(algo))
            {
                rows.Add(new TheoryDataRow<AlgoCase>(algo)
                    .WithSkip($"{algo.Name} is not supported by the installed OpenSSH client"));
                continue;
            }

            rows.Add(algo);
        }

        return rows;
    }

    private static readonly Dictionary<AlgoCategory, HashSet<string>> OpenSshCapabilities = ProbeOpenSshCapabilities();

    private static bool OpenSshShips(AlgoCase algo)
        => OpenSshCapabilities.TryGetValue(algo.Category, out var names) && names.Contains(algo.Name);

    /// <summary>Query `ssh -Q &lt;cat&gt;` once per category (host keys = key + sig union).</summary>
    private static Dictionary<AlgoCategory, HashSet<string>> ProbeOpenSshCapabilities()
    {
        var sshPath = FindSshExecutable();
        if (sshPath is null)
            return [];

        return new Dictionary<AlgoCategory, HashSet<string>>
        {
            [AlgoCategory.Kex] = [.. Query("kex")],
            [AlgoCategory.Cipher] = [.. Query("cipher")],
            [AlgoCategory.Mac] = [.. Query("mac")],
            [AlgoCategory.Compression] = [.. Query("compression")],
            // Host-key algorithms come from both the key-type list and the
            // signature list (e.g. rsa-sha2-256/512 are signature algorithms).
            [AlgoCategory.HostKey] = [.. Query("key"), .. Query("sig")],
        };

        string[] Query(string arg)
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = sshPath,
                    Arguments = $"-Q {arg}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                });
                if (p is null)
                    return [];

                var output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(5000);
                return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            }
            catch
            {
                return [];
            }
        }
    }

    // ------------------------------------------------------------------
    // SSH.NET leg: prune the client's offer to the single algorithm and
    // assert the handshake + (for cipher/MAC) a payload round-trip.
    // ------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(SshNetRows))]
    public async Task Algorithm_negotiates_via_SSH_NET(AlgoCase algo)
    {
        await using var server = TestSshServer.Create(allHostKeyAlgorithms: algo.AllHostKeys);
        RegisterPlugins(server, algo);
        server.StartListening();

        var info = AlgorithmInteropHelper.CreateConnectionInfo(server.Port);
        switch (algo.Category)
        {
            case AlgoCategory.Kex:
                AlgorithmInteropHelper.KeepOnly(info.KeyExchangeAlgorithms, algo.Name);
                break;
            case AlgoCategory.HostKey:
                AlgorithmInteropHelper.KeepOnly(info.HostKeyAlgorithms, algo.Name);
                break;
            case AlgoCategory.Cipher:
                AlgorithmInteropHelper.KeepOnly(info.Encryptions, algo.Name);
                break;
            case AlgoCategory.Mac:
                AlgorithmInteropHelper.KeepOnly(info.HmacAlgorithms, algo.Name);
                break;
            case AlgoCategory.Compression:
                AlgorithmInteropHelper.KeepOnly(info.CompressionAlgorithms, algo.Name);
                break;
        }

        using var client = new SshClient(info);
        client.Connect();

        var reported = algo.SshNetReported ?? algo.Name;
        switch (algo.Category)
        {
            case AlgoCategory.Kex:
                Assert.Equal(reported, info.CurrentKeyExchangeAlgorithm);
                break;
            case AlgoCategory.HostKey:
                Assert.Equal(reported, info.CurrentHostKeyAlgorithm);
                break;
            case AlgoCategory.Cipher:
                Assert.Equal(reported, info.CurrentClientEncryption);
                Assert.Equal(reported, info.CurrentServerEncryption);
                break;
            case AlgoCategory.Mac:
                Assert.Equal(reported, info.CurrentClientHmacAlgorithm);
                Assert.Equal(reported, info.CurrentServerHmacAlgorithm);
                break;
            case AlgoCategory.Compression:
                Assert.Equal("none", info.CurrentClientCompressionAlgorithm);
                Assert.Equal("none", info.CurrentServerCompressionAlgorithm);
                break;
        }

        // Cipher and MAC transform channel data, so a payload round-trip
        // proves the negotiated algorithm actually carried it.
        if (algo.Category is AlgoCategory.Cipher or AlgoCategory.Mac)
        {
            await using var shell = client.CreateShellStream("xterm", 80, 24, 800, 600, 8192);
            await AlgorithmInteropHelper.EchoRoundTripAsync(shell, 64 * 1024);
        }

        client.Disconnect();
        await server.DisconnectedTask.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    // ------------------------------------------------------------------
    // OpenSSH leg: force the client's offer to the single algorithm with
    // -o KexAlgorithms= / HostKeyAlgorithms= / Ciphers= / MACs= /
    // Compression=, then prove it was negotiated (-vv log) and that data
    // round-tripped over the session.
    // ------------------------------------------------------------------

    [Theory(Timeout = 60_000)]
    [MemberData(nameof(OpenSshRows))]
    public async Task Algorithm_negotiates_via_OpenSSH_client(AlgoCase algo)
    {
        // xunit.v3 cancels TestContext.Current.CancellationToken when the
        // [Theory(Timeout)] elapses, so the ssh child is killed below and the
        // run reports a timeout instead of hanging.
        var ct = TestContext.Current.CancellationToken;

        var sshPath = FindSshExecutable();
        if (sshPath is null)
        {
            Assert.Skip("OpenSSH client not installed - nothing to interop with.");
            return;
        }

        await using var server = TestSshServer.Create(allHostKeyAlgorithms: algo.AllHostKeys);
        RegisterPlugins(server, algo);
        server.StartListening();

        var keyFile = Path.Combine(Path.GetTempPath(), $"fxssh-matrix-{Guid.NewGuid():N}.key");
        var knownHosts = Path.Combine(Path.GetTempPath(), $"fxssh-matrix-known-hosts-{Guid.NewGuid():N}");

        await File.WriteAllTextAsync(keyFile, KeyGenerator.GenerateRsaKeyPem(2048), ct);

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = sshPath,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                ArgumentList =
                {
                    "-p", server.Port.ToString(),
                    "-vv",
                    "-o", ForceOption(algo),
                    // MAC rows must not ride on an AEAD cipher: GCM/chacha20's
                    // inline tag would bypass the negotiated MAC entirely.
                    "-o", algo.Category == AlgoCategory.Mac ? "Ciphers=aes256-ctr" : "Ciphers=aes256-gcm@openssh.com",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", $"UserKnownHostsFile={knownHosts}",
                    "-o", "BatchMode=yes",
                    "-i", keyFile,
                    "tester@127.0.0.1",
                    "echo hello"
                }
            };

            using var process = Process.Start(psi)!;

            await process.StandardInput.WriteAsync("hello from FxSsh\n".AsMemory(), ct);
            process.StandardInput.Close();

            var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = process.StandardError.ReadToEndAsync(ct);

            try
            {
                await Task.WhenAll(stdoutTask, stderrTask, process.WaitForExitAsync(ct));
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); }
                catch (InvalidOperationException) { /* already exited */ }

                throw;
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            Assert.True(process.ExitCode == 0, $"ssh exited with code {process.ExitCode}.\nstderr:\n{stderr}");

            // The -vv log records the negotiated algorithm by name, proving the
            // handshake really ran over it.
            Assert.Contains(algo.Name, stderr);
            Assert.Contains("hello from FxSsh", stdout);

            await server.DisconnectedTask.WaitAsync(TimeSpan.FromSeconds(10), ct);
        }
        finally
        {
            try { File.Delete(keyFile); } catch { /* Ignore file deletion errors */ }
            try { File.Delete(knownHosts); } catch { /* Ignore file deletion errors */ }
        }
    }

    /// <summary>The single-algorithm -o force for the OpenSSH client, per category.</summary>
    private static string ForceOption(AlgoCase algo) => algo.Category switch
    {
        AlgoCategory.Kex => $"KexAlgorithms={algo.Name}",
        AlgoCategory.HostKey => $"HostKeyAlgorithms={algo.Name}",
        AlgoCategory.Cipher => $"Ciphers={algo.Name}",
        AlgoCategory.Mac => $"MACs={algo.Name}",
        AlgoCategory.Compression => "Compression=no",
        _ => throw new ArgumentOutOfRangeException(nameof(algo), algo, "Unhandled algorithm category.")
    };

    /// <summary>
    /// Locate ssh.exe: prefer an upstream-built client (Git for Windows) -
    /// the Windows System32 OpenSSH client's umac128 deviates from upstream
    /// umac.c - then System32, then PATH.
    /// </summary>
    private static string? FindSshExecutable()
    {
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "usr", "bin", "ssh.exe"),
            Path.Combine(windowsDir, "System32", "OpenSSH", "ssh.exe"),
        }.Concat(
            from dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
            where dir.Length != 0
            select Path.Combine(dir.Trim('"'), "ssh.exe")
        );

        return candidates.Distinct().FirstOrDefault(File.Exists);
    }
}
