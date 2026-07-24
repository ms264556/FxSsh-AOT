using System;

namespace FxSsh.Services
{
    public abstract class SshService
    {
        protected internal readonly Session _session;

        public SshService(Session session)
        {
            ArgumentNullException.ThrowIfNull(session);

            _session = session;
        }

        internal protected abstract void CloseService();
    }
}
