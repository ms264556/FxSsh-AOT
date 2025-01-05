namespace FxSsh.Messages
{
    public class KeyExchangeECDhInitMessage : KeyExchangeXInitMessage
    {
        public byte[] Q { get; private set; }

        protected override void OnLoad(SshDataWorker reader)
        {
            Q = reader.ReadBinary();
        }
    }
}
