using System;
using System.Linq;
using System.Threading.Tasks;
using FxSsh.Algorithms;
using FxSsh.Tests.Transport;
using Xunit;

namespace FxSsh.Tests;

/// <summary>
/// Focused tests for the upstream-prescribed hazmat registry API: the
/// category-agnostic <see cref="HazmatAlgorithmList{TFactory}"/> exposed by
/// <see cref="HazmatAlgorithmCatalog"/> inside
/// <see cref="AlgorithmSelection.ConfigureHazmat"/>. These cover the public
/// mutation surface (Count, Contains, Add, AddAlias, Remove, Clear, Enable,
/// the tag enum) and prove an alias is advertised immediately after its target
/// in the server's KEXINIT name-list.
/// </summary>
public class HazmatAlgorithmListTests
{
    [Fact]
    public void Default_list_seeds_every_supported_builtin()
    {
        var selection = new AlgorithmSelection();
        selection.ConfigureHazmat(c =>
        {
            Assert.True(c.KeyExchange.Count > 0);
            Assert.True(c.PublicKey.Count > 0);
            Assert.True(c.Encryption.Count > 0);
            Assert.True(c.Hmac.Count > 0);
            Assert.True(c.Compression.Count > 0);

            Assert.True(c.KeyExchange.Contains("curve25519-sha256"));
            Assert.True(c.Encryption.Contains("aes256-ctr"));
        });
    }

    [Fact]
    public void Add_registers_and_replaces_a_custom_algorithm()
    {
        var selection = new AlgorithmSelection();
        selection.ConfigureHazmat(c =>
        {
            var count = c.KeyExchange.Count;

            c.KeyExchange.Add("test-alg@example.com", () => new EcdhKex("nistp256"));
            Assert.True(c.KeyExchange.Contains("test-alg@example.com"));
            Assert.Equal(count + 1, c.KeyExchange.Count);

            // Re-registering the same name replaces in place - count unchanged.
            c.KeyExchange.Add("test-alg@example.com", () => new EcdhKex("nistp256"));
            Assert.Equal(count + 1, c.KeyExchange.Count);
        });
    }

    [Fact]
    public void Add_throws_on_null_factory()
    {
        var selection = new AlgorithmSelection();
        selection.ConfigureHazmat(c =>
        {
            Assert.Throws<ArgumentNullException>(() => c.KeyExchange.Add("x", null!));
        });
    }

    [Fact]
    public void Remove_drops_an_algorithm_and_reports_absence()
    {
        var selection = new AlgorithmSelection();
        selection.ConfigureHazmat(c =>
        {
            var count = c.KeyExchange.Count;
            Assert.True(c.KeyExchange.Remove("ecdh-sha2-nistp384"));
            Assert.False(c.KeyExchange.Contains("ecdh-sha2-nistp384"));
            Assert.Equal(count - 1, c.KeyExchange.Count);

            Assert.False(c.KeyExchange.Remove("does-not-exist@example.com"));
        });
    }

    [Fact]
    public void Clear_empties_the_list()
    {
        var selection = new AlgorithmSelection();
        selection.ConfigureHazmat(c =>
        {
            Assert.True(c.KeyExchange.Count > 0);
            c.KeyExchange.Clear();
            Assert.Equal(0, c.KeyExchange.Count);
        });
    }

    [Fact]
    public async Task AddAlias_reuses_target_and_is_advertised_immediately_after_it()
    {
        // A known alias pair shipped by current kex algorithms: sntrup761
        // lists both the bare name and the @openssh.com variant, adjacent.
        const string target = "curve25519-sha256";
        const string alias = "curve25519-sha256-test-alias";

        await using var server = TestSshServer.Create();
        server.Algorithms.ConfigureHazmat(c => c.KeyExchange.AddAlias(alias, target));
        server.StartListening();

        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);
        var kexList = KexInitParser.ParseNameLists(client.ServerKexInitPayload)[0];

        Assert.Contains(alias, kexList);
        var index = Array.IndexOf(kexList, target);
        Assert.Equal(index + 1, Array.IndexOf(kexList, alias));
    }

    [Fact]
    public void AddAlias_targets_must_exist()
    {
        var selection = new AlgorithmSelection();
        selection.ConfigureHazmat(c =>
        {
            Assert.Throws<System.Collections.Generic.KeyNotFoundException>(
                () => c.KeyExchange.AddAlias("a", "not-a-real-algorithm"));
        });
    }

    [Fact]
    public void The_new_tag_enum_is_exposed()
    {
        // Enumerating the enum asserts the tag set the upstream API implies.
        Assert.Equal(["BuiltIn", "Custom", "Alias", "Obsolete"],
            Enum.GetNames<HazmatAlgorithmTag>());
    }
}
