
namespace FxSsh.Messages.Connection
{
    [Message("SSH_MSG_IGNORE", MessageNumber)]
    public class ShouldIgnoreMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 2;

        public override byte MessageType { get { return MessageNumber; } }

        protected override void OnLoad(SshDataReader reader)
        {
        }
    }
}
