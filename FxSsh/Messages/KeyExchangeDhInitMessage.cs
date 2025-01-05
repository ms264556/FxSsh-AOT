using System;

namespace FxSsh.Messages
{
    public class KeyExchangeDhInitMessage : KeyExchangeXInitMessage
    {
        public byte[] E { get; private set; }

        protected override void OnLoad(SshDataWorker reader)
        {
            E = reader.ReadMpint();
        }
    }
}
