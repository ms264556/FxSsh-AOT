using System;

namespace FxSsh.Services
{
    public class EnvironmentArgs
    {
        public EnvironmentArgs(SessionChannel channel, string name, string value, UserAuthArgs userAuthArgs)
        {
            ArgumentNullException.ThrowIfNull(channel);
            ArgumentNullException.ThrowIfNull(name);
            ArgumentNullException.ThrowIfNull(value);
            ArgumentNullException.ThrowIfNull(userAuthArgs);

            Channel = channel;
            Name = name;
            Value = value;
            AttachedUserAuthArgs = userAuthArgs;
        }

        public SessionChannel Channel { get; private set; }
        public string Name { get; private set; }
        public string Value { get; private set; }
        public UserAuthArgs AttachedUserAuthArgs { get; private set; }
    }
}
