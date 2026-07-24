using System;

namespace FxSsh.Messages
{
    [AttributeUsage(AttributeTargets.Class, Inherited = true, AllowMultiple = false)]
    public sealed class MessageAttribute : Attribute
    {
        public MessageAttribute(string name, byte number)
        {
            ArgumentNullException.ThrowIfNull(name);

            Name = name;
            Number = number;
        }

        public string Name { get; private set; }
        public byte Number { get; private set; }
    }
}
