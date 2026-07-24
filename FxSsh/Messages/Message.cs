using System;

namespace FxSsh.Messages
{
    public abstract class Message
    {
        public abstract byte MessageType { get; }

        protected ReadOnlyMemory<byte> RawBytes { get; set; }

        public void Load(ReadOnlyMemory<byte> bytes)
        {
            RawBytes = bytes;

            var reader = new SshDataReader(bytes);
            var number = reader.ReadByte();
            if (number != MessageType)
                throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

            OnLoad(reader);
        }

        public byte[] GetPacket()
        {
            var writer = new SshDataWriter();
            writer.Write(MessageType);

            OnGetPacket(writer);

            return writer.ToByteArray();
        }

        public static T LoadFrom<T>(Message message) where T : Message, new()
        {
            ArgumentNullException.ThrowIfNull(message);

            var msg = new T();
            msg.Load(message.RawBytes);
            return msg;
        }

        protected virtual void OnLoad(SshDataReader reader)
        {
            ArgumentNullException.ThrowIfNull(reader);

            throw new NotSupportedException();
        }

        protected virtual void OnGetPacket(SshDataWriter writer)
        {
            ArgumentNullException.ThrowIfNull(writer);

            throw new NotSupportedException();
        }
    }
}
