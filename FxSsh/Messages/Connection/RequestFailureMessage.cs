
namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// SSH_MSG_REQUEST_FAILURE (82) per RFC 4254 section 4.
    /// Reply to SSH_MSG_GLOBAL_REQUEST with want-reply true. No payload.
    /// </summary>
    [Message("SSH_MSG_REQUEST_FAILURE", MessageNumber)]
    public class RequestFailureMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 82;

        public override byte MessageType { get { return MessageNumber; } }

        protected override void OnLoad(SshDataReader reader)
        {
            // No payload per RFC 4254 section 4.
        }

        protected override void OnGetPacket(SshDataWriter writer)
        {
        }
    }
}
