using System;
using System.Threading.Tasks;
using FxSsh.Tests.Transport;
using Renci.SshNet;
using Renci.SshNet.Common;
using Xunit;

namespace FxSsh.Tests;

/// <summary>
/// Proves AlgorithmSelection is genuinely pluggable: mutations to the
/// server's algorithm registry are reflected in the advertised KEXINIT
/// name-lists and in real negotiation, without touching the library.
/// </summary>
public class AlgorithmSelectionTests
{
    [Fact]
    public async Task Removed_algorithm_is_no_longer_advertised()
    {
        await using var server = TestSshServer.Start();
        server.Algorithms.ConfigureHazmat(c => c.KeyExchange.Remove("ecdh-sha2-nistp384"));

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
        server.Algorithms.ConfigureHazmat(c => c.KeyExchange.Add("test-kex@example.com",
            () => throw new NotSupportedException("test-kex@example.com must never be negotiated")));

        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);
        var kexList = ParseKexNameList(client.ServerKexInitPayload);

        Assert.Contains("test-kex@example.com", kexList);
    }

    [Fact]
    public async Task Removed_algorithm_fails_negotiation_with_SSH_NET()
    {
        await using var server = TestSshServer.Start();
        server.Algorithms.ConfigureHazmat(c => c.KeyExchange.Remove("diffie-hellman-group14-sha256"));

        var info = AlgorithmInteropHelper.CreateConnectionInfo(server.Port);
        AlgorithmInteropHelper.KeepOnly(info.KeyExchangeAlgorithms, "diffie-hellman-group14-sha256");

        using var client = new SshClient(info);
        // The client can only offer the removed algorithm, so the handshake
        // must fail instead of silently negotiating something else.
        Assert.ThrowsAny<SshException>(client.Connect);
    }

    /// <summary>Extract the kex_algorithms name-list (the first of the ten) from a KEXINIT payload.</summary>
    private static string[] ParseKexNameList(byte[] payload)
        => KexInitParser.ParseNameLists(payload)[0];
}
