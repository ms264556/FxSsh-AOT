using System.Text;

namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_CHANNEL_OPEN_FAILURE", MessageNumber)]
    public class ChannelOpenFailureMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 92;

        public uint RecipientChannel { get; set; }
        public ChannelOpenFailureReason ReasonCode { get; set; }
        public string Description { get; set; }
        public string Language { get; set; }

        public override byte MessageType { get { return MessageNumber; } }

        protected override void OnLoad(SshDataReader reader)
        {
            RecipientChannel = reader.ReadUInt32();
            ReasonCode = (ChannelOpenFailureReason)reader.ReadUInt32();
            Description = reader.ReadString(Encoding.ASCII);
            Language = reader.ReadString(Encoding.ASCII);
        }

        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(RecipientChannel);
            writer.Write((uint)ReasonCode);
            writer.Write(Description, Encoding.ASCII);
            writer.Write(Language ?? "en", Encoding.ASCII);
        }
    }
}
