using System;

namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_CHANNEL_DATA", MessageNumber)]
    public class ChannelDataMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 94;

        public uint RecipientChannel { get; set; }
        public ReadOnlyMemory<byte> Data { get; set; }

        public override byte MessageType { get { return MessageNumber; } }

        protected override void OnLoad(SshDataReader reader)
        {
            RecipientChannel = reader.ReadUInt32();
            // Zero-copy: keep the slice over the decoded packet buffer rather
            // than ToArray()'ing into a fresh allocation. The packet buffer
            // is retained by Session.ReceiveMessage until LoadMessage returns,
            // which is synchronous here, so the slice stays valid for the
            // downstream OnData -> DataReceived -> consumer pump all of which
            // run on the same ConnectionService message loop thread before
            // the next ReceiveMessage reuses the buffer.
            Data = reader.ReadBinaryAsMemory();
        }

        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(RecipientChannel);
            writer.WriteBinary(Data);
        }
    }
}
