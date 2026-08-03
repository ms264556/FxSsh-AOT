
namespace FxSsh.Algorithms
{
    public enum CipherModeEx
    {
        CBC,
        CTR,

        /// <summary>
        /// AES-GCM AEAD mode for aes128-gcm@openssh.com / aes256-gcm@openssh.com
        /// (RFC 5647). Unlike CBC/CTR this is Authenticated Encryption - the
        /// GCM tag replaces the separate HMAC field, so the Session send/receive
        /// paths branch on IsAead instead of computing an HMAC.
        /// </summary>
        GCM,
    }
}
