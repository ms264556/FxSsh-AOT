using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace FxSsh.Messages
{
    [Message("SSH_MSG_KEXINIT", MessageNumber)]
    public class KeyExchangeInitMessage : Message
    {
        private const byte MessageNumber = 20;

        public KeyExchangeInitMessage()
        {
            Cookie = RandomNumberGenerator.GetBytes(16);
        }

        public byte[] Cookie { get; private set; }

        public string[] KeyExchangeAlgorithms { get; set; }

        public string[] ServerHostKeyAlgorithms { get; set; }

        public string[] EncryptionAlgorithmsClientToServer { get; set; }

        public string[] EncryptionAlgorithmsServerToClient { get; set; }

        public string[] MacAlgorithmsClientToServer { get; set; }

        public string[] MacAlgorithmsServerToClient { get; set; }

        public string[] CompressionAlgorithmsClientToServer { get; set; }

        public string[] CompressionAlgorithmsServerToClient { get; set; }

        public string[] LanguagesClientToServer { get; set; }

        public string[] LanguagesServerToClient { get; set; }

        public bool FirstKexPacketFollows { get; set; }

        public uint Reserved { get; set; }

        /// <summary>
        /// Extension identifiers (RFC 8308) parsed from the reserved area of
        /// a received KEXINIT (set on the client side). Each remaining byte
        /// sequence after Reserved is an extension name string.
        /// This is populated only when parsing a received message; the send
        /// path uses <see cref="ExtensionNames"/> instead.
        /// </summary>
        public HashSet<string> PeerExtensions { get; private set; } = [];

        /// <summary>
        /// Extension names to include in the sent KEXINIT (e.g. "ext-info-s").
        /// Set before calling <see cref="OnGetPacket(SshDataWriter)"/>.
        /// </summary>
        public HashSet<string> ExtensionNames { get; set; } = [];

        public override byte MessageType { get { return MessageNumber; } }

        protected override void OnLoad(SshDataReader reader)
        {
            Cookie = reader.ReadBytes(16);
            KeyExchangeAlgorithms = reader.ReadString(Encoding.ASCII).Split(',');
            ServerHostKeyAlgorithms = reader.ReadString(Encoding.ASCII).Split(',');
            EncryptionAlgorithmsClientToServer = reader.ReadString(Encoding.ASCII).Split(',');
            EncryptionAlgorithmsServerToClient = reader.ReadString(Encoding.ASCII).Split(',');
            MacAlgorithmsClientToServer = reader.ReadString(Encoding.ASCII).Split(',');
            MacAlgorithmsServerToClient = reader.ReadString(Encoding.ASCII).Split(',');
            CompressionAlgorithmsClientToServer = reader.ReadString(Encoding.ASCII).Split(',');
            CompressionAlgorithmsServerToClient = reader.ReadString(Encoding.ASCII).Split(',');
            LanguagesClientToServer = reader.ReadString(Encoding.ASCII).Split(',');
            LanguagesServerToClient = reader.ReadString(Encoding.ASCII).Split(',');
            FirstKexPacketFollows = reader.ReadBoolean();
            Reserved = reader.ReadUInt32();

            // RFC 4253 section 4: reserved is the last field of the KEXINIT
            // payload. Per RFC 8308, the "ext-info-c" / "ext-info-s" extension
            // markers are advertised inside the kex_algorithms name-list (NOT
            // in a trailing name-list after reserved). OpenSSH also appends
            // "kex-strict-c-v00@openssh.com" to the same list. We therefore
            // detect extension support from KeyExchangeAlgorithms, and ignore
            // any trailing bytes after reserved (some clients append a stray
            // zero byte; RFC 4253 treats the payload as ending at reserved).
            PeerExtensions = [];
            foreach (var kex in KeyExchangeAlgorithms)
            {
                if (kex == "ext-info-c" || kex == "ext-info-s")
                    PeerExtensions.Add(kex);
            }
        }

        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.WriteBytes(Cookie);
            writer.Write(string.Join(",", KeyExchangeAlgorithms), Encoding.ASCII);
            writer.Write(string.Join(",", ServerHostKeyAlgorithms), Encoding.ASCII);
            writer.Write(string.Join(",", EncryptionAlgorithmsClientToServer), Encoding.ASCII);
            writer.Write(string.Join(",", EncryptionAlgorithmsServerToClient), Encoding.ASCII);
            writer.Write(string.Join(",", MacAlgorithmsClientToServer), Encoding.ASCII);
            writer.Write(string.Join(",", MacAlgorithmsServerToClient), Encoding.ASCII);
            writer.Write(string.Join(",", CompressionAlgorithmsClientToServer), Encoding.ASCII);
            writer.Write(string.Join(",", CompressionAlgorithmsServerToClient), Encoding.ASCII);
            writer.Write(string.Join(",", LanguagesClientToServer), Encoding.ASCII);
            writer.Write(string.Join(",", LanguagesServerToClient), Encoding.ASCII);
            writer.Write(FirstKexPacketFollows);
            writer.Write(Reserved);

            // RFC 8308: ext-info-s is advertised inside the kex_algorithms
            // name-list (NOT as a trailing field after reserved). It is
            // already included via KeyExchangeAlgorithms by the caller.
        }
    }
}
