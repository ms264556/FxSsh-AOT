
namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// SSH_MSG_REQUEST_SUCCESS (81) per RFC 4254 section 4.
    /// Reply to SSH_MSG_GLOBAL_REQUEST with want-reply true. No payload.
    /// </summary>
    [Message("SSH_MSG_REQUEST_SUCCESS", MessageNumber)]
    public class RequestSuccessMessage : ConnectionServiceMessage
    {
        private const byte MessageNumber = 81;

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
