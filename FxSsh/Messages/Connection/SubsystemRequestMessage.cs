using System.Text;
using FxSsh.Messages.Connection;

namespace FxSsh.Messages
{
    public class SubsystemRequestMessage : ChannelRequestMessage
    {
        public string Name { get; private set; }

        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            Name = reader.ReadString(Encoding.ASCII);
        }
    }
}
