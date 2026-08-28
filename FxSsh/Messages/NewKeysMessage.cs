namespace FxSsh.Messages
{
    [Message("SSH_MSG_NEWKEYS", MessageNumber)]
    public class NewKeysMessage : Message
    {
        internal const byte MessageNumber = 21;

        public override byte MessageType { get { return MessageNumber; } }

        protected override void OnLoad(SshDataReader reader)
        {
        }

        protected override void OnGetPacket(SshDataWriter writer)
        {
        }
    }
}
