using System;

namespace FxSsh.Messages.UserAuth
{
    public class NoneRequestMessage : RequestMessage
    {
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            if (MethodName != "none")
                throw new ArgumentException(string.Format("Method name {0} is not valid.", MethodName));
        }
    }
}
