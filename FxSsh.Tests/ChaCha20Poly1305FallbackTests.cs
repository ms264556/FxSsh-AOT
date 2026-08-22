using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using FxSsh.Tests.Algorithms;
using Xunit;

namespace FxSsh.Tests;

/// <summary>
/// Correctness tests for the hand-rolled ChaCha20 keystream kernel inside
/// ChaCha20Poly1305Transform - the vectorized fallback used on platforms
/// without native ChaCha20Poly1305 support (forced with the internal
/// forceManagedKeystream ctor flag). The interop matrix exercises the BCL
/// path, so these tests pin the fallback to the same OpenSSL-verified
/// reference bytes and prove both keystream paths are byte-identical.
/// </summary>
public class ChaCha20Poly1305FallbackTests
{
    // 64-byte client-to-server key from the draft's Figure 5.
    private static readonly byte[] Key =
    [
        0x8B, 0xBF, 0xF6, 0x85, 0x5F, 0xC1, 0x02, 0x33, 0x8C, 0x37, 0x3E, 0x73, 0xAA, 0xC0, 0xC9, 0x14,
        0xF0, 0x76, 0xA9, 0x05, 0xB2, 0x44, 0x4A, 0x32, 0xEE, 0xCA, 0xFF, 0xEA, 0xD2, 0x2B, 0xEC, 0xC5,
        0xE9, 0xB7, 0xA7, 0xA5, 0x82, 0x5A, 0x82, 0x49, 0x34, 0x6E, 0xC1, 0xC2, 0x83, 0x01, 0xCF, 0x39,
        0x45, 0x43, 0xFC, 0x75, 0x69, 0x88, 0x7D, 0x76, 0xE1, 0x68, 0xF3, 0x75, 0x62, 0xAC, 0x07, 0x40,
    ];

    // Figure 4: packet_length(4) | padding_length(1) | SSH_MSG_CHANNEL_DATA(1)
    // | recipient(4) | string(4+56) | padding(6).
    private static readonly byte[] Frame =
    [
        0x00, 0x00, 0x00, 0x48, 0x06, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x4C, 0x6F,
        0x72, 0x65, 0x6D, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6D, 0x20, 0x64, 0x6F, 0x6C, 0x6F, 0x72, 0x20,
        0x73, 0x69, 0x74, 0x20, 0x61, 0x6D, 0x65, 0x74, 0x2C, 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x65, 0x63,
        0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x69, 0x63, 0x69, 0x6E,
        0x67, 0x20, 0x65, 0x6C, 0x69, 0x74, 0x4E, 0x43, 0xE8, 0x04, 0xDC, 0x6C,
    ];

    // Encrypted length (matches the draft's Figure 8: 2c3ecce4) || payload
    // ciphertext || Poly1305 auth tag, computed with OpenSSL 3.2.3 (an
    // independent implementation of the same construction).
    private static readonly byte[] ExpectedWire =
    [
        0x2C, 0x3E, 0xCC, 0xE4, 0xFB, 0xC0, 0x5C, 0x54, 0x53, 0x51, 0x4A, 0x75, 0xF5, 0x47, 0x9D, 0xBC,
        0xFC, 0xAF, 0xC9, 0x7F, 0xC8, 0x80, 0xBD, 0xA2, 0xC6, 0x59, 0xAB, 0xA5, 0x24, 0x45, 0xE0, 0x66,
        0x0B, 0xEA, 0x38, 0x36, 0xFA, 0xC9, 0x91, 0x6B, 0x26, 0x28, 0x7C, 0xD1, 0x2F, 0xA5, 0xB2, 0x02,
        0x53, 0x1B, 0x58, 0xE2, 0x16, 0x3F, 0xCA, 0xAF, 0x61, 0x02, 0xC0, 0xB3, 0x65, 0x8C, 0x04, 0x4F,
        0x62, 0x95, 0xE8, 0xAA, 0x7E, 0xD1, 0x68, 0x22, 0xE3, 0x6A, 0xC7, 0xC3, 0x56, 0xF9, 0x79, 0x5B,
        0x0A, 0xA6, 0x14, 0x41, 0xC3, 0xEF, 0x45, 0x81, 0xAA, 0x10, 0x35, 0xFA,
    ];

    /// <summary>The hand-rolled kernel must produce the exact OpenSSL-verified wire bytes.</summary>
    [Fact]
    public void Hand_rolled_kernel_encrypts_draft_worked_example_to_expected_wire_bytes()
    {
        var transform = new ChaCha20Poly1305Transform(Key, forceManagedKeystream: true);
        var wire = new byte[Frame.Length + ChaCha20Poly1305Transform.TagSize];
        transform.Encrypt(sequenceNumber: 7, Frame, wire);
        Assert.Equal(ExpectedWire, wire);
    }

    /// <summary>The hand-rolled kernel must decrypt the reference wire packet back to the draft frame.</summary>
    [Fact]
    public void Hand_rolled_kernel_decrypts_length_and_payload()
    {
        var transform = new ChaCha20Poly1305Transform(Key, forceManagedKeystream: true);

        // The length field is encrypted on the wire: DecryptPacketLength must
        // recover the plaintext 0x48 before the body can be read.
        Assert.Equal(0x48, transform.DecryptPacketLength(7, ExpectedWire.AsSpan(0, 4)));

        var plain = new byte[0x48];
        transform.Decrypt(7, ExpectedWire.AsSpan(0, 4), ExpectedWire.AsSpan(4), plain);
        Assert.Equal(Frame.AsSpan(4).ToArray(), plain);
    }

    /// <summary>
    /// The fallback kernel and the BCL keystream path must be byte-identical
    /// for the same key, frame and sequence number (including cross-decrypt).
    /// </summary>
    [Fact]
    public void Hand_rolled_kernel_matches_bcl_path_byte_for_byte()
    {
        var key = RandomNumberGenerator.GetBytes(ChaCha20Poly1305Transform.KeySize);
        var bcl = new ChaCha20Poly1305Transform(key);
        var handrolled = new ChaCha20Poly1305Transform(key, forceManagedKeystream: true);

        foreach (var bodySize in new[] { 16, 1024, 32 * 1024 })
        {
            var frame = new byte[4 + bodySize];
            RandomNumberGenerator.Fill(frame);
            BinaryPrimitives.WriteInt32BigEndian(frame, bodySize);

            foreach (var seq in new uint[] { 0, 1, 7, UInt32.MaxValue })
            {
                var wireBcl = new byte[frame.Length + ChaCha20Poly1305Transform.TagSize];
                var wireHand = new byte[frame.Length + ChaCha20Poly1305Transform.TagSize];
                bcl.Encrypt(seq, frame, wireBcl);
                handrolled.Encrypt(seq, frame, wireHand);

                Assert.Equal(wireBcl, wireHand);

                // Cross-decrypt: each kernel must decrypt the other's ciphertext.
                var plainFromHand = new byte[bodySize];
                handrolled.Decrypt(seq, wireBcl.AsSpan(0, 4), wireBcl.AsSpan(4), plainFromHand);
                Assert.Equal(frame.AsSpan(4).ToArray(), plainFromHand);

                var plainFromBcl = new byte[bodySize];
                bcl.Decrypt(seq, wireHand.AsSpan(0, 4), wireHand.AsSpan(4), plainFromBcl);
                Assert.Equal(frame.AsSpan(4).ToArray(), plainFromBcl);
            }
        }
    }

    /// <summary>Self-consistency across sequence numbers on the fallback kernel alone.</summary>
    [Fact]
    public void Hand_rolled_kernel_round_trips_across_sequence_numbers()
    {
        var transform = new ChaCha20Poly1305Transform(Key, forceManagedKeystream: true);
        var frame = RandomNumberGenerator.GetBytes(4 + 1000);
        // A real frame's packet_length field must equal the body size.
        BinaryPrimitives.WriteInt32BigEndian(frame, frame.Length - 4);

        foreach (var seq in new uint[] { 0, 1, 7, 42, UInt32.MaxValue })
        {
            var wire = new byte[frame.Length + ChaCha20Poly1305Transform.TagSize];
            transform.Encrypt(seq, frame, wire);

            var packetLength = transform.DecryptPacketLength(seq, wire.AsSpan(0, 4));
            Assert.Equal(frame.Length - 4, packetLength);

            var plain = new byte[frame.Length - 4];
            transform.Decrypt(seq, wire.AsSpan(0, 4), wire.AsSpan(4), plain);
            Assert.Equal(frame.AsSpan(4).ToArray(), plain);
        }
    }
}
