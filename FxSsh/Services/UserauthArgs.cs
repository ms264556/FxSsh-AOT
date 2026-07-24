using System;

namespace FxSsh.Services
{
    public class UserAuthArgs
    {
        public UserAuthArgs(Session session)
        {
            AuthMethod = "none";
            Session = session;
        }

        public UserAuthArgs(Session session, string username, string keyAlgorithm, string fingerprint, byte[] key)
        {
            ArgumentNullException.ThrowIfNull(keyAlgorithm);
            ArgumentNullException.ThrowIfNull(fingerprint);
            ArgumentNullException.ThrowIfNull(key);

            AuthMethod = "publickey";
            KeyAlgorithm = keyAlgorithm;
            Fingerprint = fingerprint;
            Key = key;
            Session = session;
            Username = username;
        }

        public UserAuthArgs(Session session, string username, string password)
        {
            ArgumentNullException.ThrowIfNull(username);
            ArgumentNullException.ThrowIfNull(password);

            AuthMethod = "password";
            Username = username;
            Password = password;
            Session = session;
        }

        public string AuthMethod { get; private set; }
        public Session Session { get; private set; }
        public string Username { get; private set; }
        public string Password { get; private set; }
        public string KeyAlgorithm { get; private set; }
        public string Fingerprint { get; private set; }
        public byte[] Key { get; private set; }
        public bool Result { get; set; }
    }
}
