using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// SSH_MSG_CHANNEL_REQUEST "exit-signal" per RFC 4254 section 10.2.
    /// Sent instead of exit-status when the process was terminated by a signal.
    /// </summary>
    public class ExitSignalMessage : ChannelRequestMessage
    {
        /// <summary>
        /// Signal name WITHOUT the "SIG" prefix (e.g. "TERM", "KILL", "SEGV"),
        /// or "SEGV" / core-dump indicator per RFC 4254 section 10.2.
        /// </summary>
        public string SignalName { get; set; }

        /// <summary>
        /// True if the process terminated due to a core dump.
        /// </summary>
        public bool CoreDumped { get; set; }

        /// <summary>
        /// Human-readable explanation (may be empty).
        /// </summary>
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Language tag per RFC 3066 (e.g. "en").
        /// </summary>
        public string Language { get; set; } = "en";

        protected override void OnGetPacket(SshDataWriter writer)
        {
            RequestType = "exit-signal";
            WantReply = false;

            base.OnGetPacket(writer);

            writer.Write(SignalName ?? string.Empty, Encoding.ASCII);
            writer.Write(CoreDumped);
            writer.Write(ErrorMessage ?? string.Empty, Encoding.UTF8);
            writer.Write(Language ?? "en", Encoding.ASCII);
        }
    }
}
