using System;
using System.Threading.Tasks;
using FxSsh.Tests.Algorithms;
using FxSsh.Tests.Transport;
using Renci.SshNet;
using Renci.SshNet.Common;
using Xunit;

namespace FxSsh.Tests;

/// <summary>
/// Proves the server's algorithm configuration surface (HazMat) is genuinely
/// pluggable: mutations to its algorithm dictionaries are reflected in the
/// advertised KEXINIT
/// name-lists and in real negotiation, without touching the library.
/// </summary>
public class SupportedAlgorithmsTests
{
    [Fact]
    public async Task Removed_algorithm_is_no_longer_advertised()
    {
        await using var server = TestSshServer.Start();
        server.HazMat.KeyExchange.Remove("ecdh-sha2-nistp384");

        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);
        var kexList = ParseKexNameList(client.ServerKexInitPayload);

        Assert.DoesNotContain("ecdh-sha2-nistp384", kexList);
        // Control: the remaining algorithms are still advertised.
        Assert.Contains("ecdh-sha2-nistp256", kexList);
    }

    [Fact]
    public async Task Added_algorithm_is_advertised()
    {
        await using var server = TestSshServer.Start();
        // The factory throws if ever invoked: advertising alone must not
        // instantiate the algorithm.
        server.HazMat.KeyExchange.Add("test-kex@example.com",
            () => throw new NotSupportedException("test-kex@example.com must never be negotiated"));

        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);
        var kexList = ParseKexNameList(client.ServerKexInitPayload);

        Assert.Contains("test-kex@example.com", kexList);
    }

    [Fact]
    public async Task Removed_algorithm_fails_negotiation_with_SSH_NET()
    {
        await using var server = TestSshServer.Start();
        server.HazMat.KeyExchange.Remove("diffie-hellman-group14-sha256");

        var info = AlgorithmInteropHelper.CreateConnectionInfo(server.Port);
        AlgorithmInteropHelper.KeepOnly(info.KeyExchangeAlgorithms, "diffie-hellman-group14-sha256");

        using var client = new SshClient(info);
        // The client can only offer the removed algorithm, so the handshake
        // must fail instead of silently negotiating something else.
        Assert.ThrowsAny<SshException>(client.Connect);
    }

    /// <summary>
    /// Idiomatic Configure hook: a single callback can Clear/Add/Remove/Insert
    /// across the algorithm categories, and every mutation is reflected in the
    /// advertised KEXINIT name-lists.
    /// </summary>
    [Fact]
    public async Task Configure_algorithms_rebuilds_the_negotiable_set()
    {
        await using var server = TestSshServer.Start();
        server.HazMat.OverrideSafeAlgorithmDefaults(sel =>
        {
            // Rebuild key exchange to a single pinned algorithm.
            var kex = sel.KeyExchange;
            kex.Clear();
            kex.Add("sntrup761x25519-sha512", () => new Sntrup761X25519Kex());

            // Drop a default host key and pin ssh-ed25519 to the top of the list.
            var pk = sel.PublicKey;
            pk.Remove("ecdsa-sha2-nistp521");
            pk.Insert(0, "ssh-ed25519", key => new Ed25519Key(key));
        });
        server.AddHostKey("ssh-ed25519", Ed25519Key.GenerateKeyPem());

        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);
        var lists = KexInitParser.ParseNameLists(client.ServerKexInitPayload);

        // KEX: only the pinned algorithm is advertised (ext-info-s is appended).
        Assert.Contains("sntrup761x25519-sha512", lists[0]);
        Assert.DoesNotContain("ecdh-sha2-nistp256", lists[0]);

        // Host key: ecdsa-sha2-nistp521 is dropped, ssh-ed25519 is advertised first.
        Assert.DoesNotContain("ecdsa-sha2-nistp521", lists[1]);
        Assert.StartsWith("ssh-ed25519", string.Join(",", lists[1]));
    }

    /// <summary>Extract the kex_algorithms name-list (the first of the ten) from a KEXINIT payload.</summary>
    private static string[] ParseKexNameList(byte[] payload)
        => KexInitParser.ParseNameLists(payload)[0];
}
