using FxSsh.Algorithms;
using FxSsh.Logging;
using FxSsh.Messages;
using FxSsh.Messages.Connection;
using FxSsh.Services;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace FxSsh
{
    public class Session
    {
        private const byte CarriageReturn = 0x0d;
        private const byte LineFeed = 0x0a;
        internal const int MaximumSshPacketSize = LocalChannelDataPacketSize;
        internal const int InitialLocalWindowSize = LocalChannelDataPacketSize * 32;
        internal const int LocalChannelDataPacketSize = 1024 * 32;
        // RFC 4253 §6.1: all implementations MUST be able to process packets with
        // a total size of 35000 bytes or less; anything larger is rejected to
        internal const int MaximumPacketLength = 35000;
        // RFC 4253 §6: minimum packet size is 16 bytes total, i.e. packet_length >= 12.
        internal const int MinimumPacketLength = 12;

        private static readonly Dictionary<byte, Type> _messagesMetadata;
        internal static readonly Dictionary<string, Func<KexAlgorithm>> _keyExchangeAlgorithms = [];
        internal static readonly Dictionary<string, Func<string, PublicKeyAlgorithm>> _publicKeyAlgorithms = [];
        internal static readonly Dictionary<string, Func<CipherInfo>> _encryptionAlgorithms = [];
        internal static readonly Dictionary<string, Func<HmacInfo>> _hmacAlgorithms = [];
        internal static readonly Dictionary<string, Func<CompressionAlgorithm>> _compressionAlgorithms = [];

        private readonly object _locker = new();
        private Socket _socket;
        private bool _disconnected;
#if DEBUG
        private readonly TimeSpan _timeout = TimeSpan.FromDays(1);
#else
        private readonly TimeSpan _timeout = TimeSpan.FromSeconds(30);
#endif
        private readonly Dictionary<string, string> _hostKey;

        // Server-side keepalive. IdleThreshold is both the idle threshold that
        // starts the probing and the resend cadence once probing has started.
        // Probes are counted; MaxMissedProbes unanswered probes disconnect the
        // session. Both directions of traffic refresh _lastActivity (sending a
        // frame also proves the link is alive and advances the peer's ACK).
        private const int MaxMissedProbes = 3;
        private TimeSpan _keepaliveIdle = TimeSpan.Zero;   // <=0 means disabled
        private Stopwatch _lastActivity;
        private int _missedProbes;
        private Timer _keepaliveTimer;

        private uint _outboundPacketSequence;
        private uint _inboundPacketSequence;
        private uint _outboundFlow;
        private uint _inboundFlow;
        private Algorithms _algorithms = null;
        private ExchangeContext _exchangeContext = null;
        private List<SshService> _services = [];

        // Protocol extensions (RFC 8308)
        private Dictionary<string, string> _extensionsToSend = [];
        private bool _clientAdvertisedExtInfo;  // client KEXINIT had "ext-info-c"
        private ConcurrentQueue<Message> _blockedMessages = new();
        private EventWaitHandle _hasBlockedMessagesWaitHandle = new ManualResetEvent(true);

        // Reusable outbound buffers. SendMessageInternal is always serialized
        // (under _locker via SendMessage, or inside the NEWKEYS
        // blocked-message window), so these can be reused across packets with
        // zero per-packet heap allocation:
        //   _sendScratchBuffer — plaintext frame [packet_length][padding_length][payload][padding]
        //   _sendBuffer       — final wire packet (ciphertext + tag/MAC)
        private readonly byte[] _sendScratchBuffer = new byte[4 + MaximumPacketLength + 255];
        private readonly byte[] _sendBuffer = new byte[4 + MaximumPacketLength + 255 + 64];

        public string ServerVersion { get; private set; }
        public string ClientVersion { get; private set; }
        public byte[] SessionId { get; private set; }
        public T GetService<T>() where T : SshService
        {
            return (T)_services.FirstOrDefault(x => x is T);
        }

        static Session()
        {
            _keyExchangeAlgorithms.Add("ecdh-sha2-nistp256", () => new EcdhKex("nistp256"));
            _keyExchangeAlgorithms.Add("ecdh-sha2-nistp384", () => new EcdhKex("nistp384"));
            _keyExchangeAlgorithms.Add("ecdh-sha2-nistp521", () => new EcdhKex("nistp521"));
            _keyExchangeAlgorithms.Add("diffie-hellman-group18-sha512", () => new DiffieHellmanKex(512, 8192));
            _keyExchangeAlgorithms.Add("diffie-hellman-group16-sha512", () => new DiffieHellmanKex(512, 4096));
            _keyExchangeAlgorithms.Add("diffie-hellman-group14-sha256", () => new DiffieHellmanKex(256, 2048));

            _publicKeyAlgorithms.Add("ecdsa-sha2-nistp256", x => new EcdsaKey("nistp256", x));
            _publicKeyAlgorithms.Add("ecdsa-sha2-nistp384", x => new EcdsaKey("nistp384", x));
            _publicKeyAlgorithms.Add("ecdsa-sha2-nistp521", x => new EcdsaKey("nistp521", x));
            _publicKeyAlgorithms.Add("rsa-sha2-256", x => new RsaKey(256, x));
            _publicKeyAlgorithms.Add("rsa-sha2-512", x => new RsaKey(512, x));

            _encryptionAlgorithms.Add("aes256-ctr", () => new CipherInfo(Aes.Create(), 256, CipherModeEx.CTR));
            _encryptionAlgorithms.Add("aes256-gcm@openssh.com", () => new CipherInfo(256));
            _encryptionAlgorithms.Add("aes128-gcm@openssh.com", () => new CipherInfo(128));

            _hmacAlgorithms.Add("hmac-sha2-256", () => new HmacInfo(new HMACSHA256(), 256));
            _hmacAlgorithms.Add("hmac-sha2-512", () => new HmacInfo(new HMACSHA512(), 512));
            _hmacAlgorithms.Add("hmac-sha2-256-etm@openssh.com", () => new HmacInfo(new HMACSHA256(), 256, true));
            _hmacAlgorithms.Add("hmac-sha2-512-etm@openssh.com", () => new HmacInfo(new HMACSHA512(), 512, true));

            _compressionAlgorithms.Add("none", () => new NoCompression());

            _messagesMetadata = (from t in typeof(Message).Assembly.GetTypes()
                                 let attrib = (MessageAttribute)t.GetCustomAttributes(typeof(MessageAttribute), false).FirstOrDefault()
                                 where attrib != null
                                 select new { attrib.Number, Type = t })
                                 .ToDictionary(x => x.Number, x => x.Type);
        }

        public Session(Socket socket, Dictionary<string, string> hostKey, string serverBanner)
        {
            ArgumentNullException.ThrowIfNull(socket);
            ArgumentNullException.ThrowIfNull(hostKey);

            _socket = socket;
            _hostKey = hostKey.ToDictionary(s => s.Key, s => s.Value);
            ServerVersion = serverBanner;
        }

        public event EventHandler<EventArgs> Disconnected;

        public event EventHandler<SshService> ServiceRegistered;

        public event EventHandler<KeyExchangeArgs> KeysExchanged;

        internal void EstablishConnection()
        {
            if (!_socket.Connected)
            {
                return;
            }

            SetSocketOptions();

            SocketWriteProtocolVersion();
            ClientVersion = SocketReadProtocolVersion();
            Log.Info($"Client version: {ClientVersion}.");
            if (!Regex.IsMatch(ClientVersion, "SSH-2.0-.+"))
            {
                Log.Warn($"Unsupported client SSH version: {ClientVersion}.");
                throw new SshConnectionException(
                    string.Format("Not supported for client SSH version {0}. This server only supports SSH v2.0.", ClientVersion),
                    DisconnectReason.ProtocolVersionNotSupported);
            }

            Log.Debug("Session established, starting key exchange.");
            ConsiderReExchange(true);

            try
            {
                while (!_disconnected && _socket != null && _socket.Connected)
                {
                    var message = ReceiveMessage();
                    if (message is UnknownMessage unknownMessage)
                    {
                        Log.Debug($"Unknown message type {((UnknownMessage)message).UnknownMessageType}, replying SSH_MSG_UNIMPLEMENTED.");
                        SendMessage(unknownMessage.MakeUnimplementedMessage());
                    }
                    else
                        HandleMessageCore(message);
                }
            }
            finally
            {
                foreach (var service in _services)
                {
                    service.CloseService();
                }

                Disconnect();
            }
        }

        public void Disconnect(DisconnectReason reason = DisconnectReason.ByApplication, string description = "Connection terminated by the server.")
        {
            bool runTeardown;
            lock (_locker)
            {
                runTeardown = !_disconnected;
                _disconnected = true;
            }
            if (!runTeardown)
            {
                return;
            }

            _keepaliveTimer?.Dispose();
            _keepaliveTimer = null;

            if (reason == DisconnectReason.ByApplication)
            {
                var message = new DisconnectMessage(reason, description);
                TrySendMessage(message);
            }

            try
            {
                _socket.Shutdown(SocketShutdown.Both);
                _socket.Close();
                _socket.Dispose();
            }
            catch { }
            finally
            {
                _socket = null;
            }

            Log.Info($"Session disconnected: {reason} - {description}");
            Disconnected?.Invoke(this, EventArgs.Empty);
        }

        #region Socket operations
        private void SetSocketOptions()
        {
            const int socketBufferSize = 2 * MaximumSshPacketSize;
            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            _socket.LingerState = new LingerOption(enable: false, seconds: 0);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, socketBufferSize);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, socketBufferSize);
            _socket.ReceiveTimeout = (int)_timeout.TotalMilliseconds;
        }

        private string SocketReadProtocolVersion()
        {
            // http://tools.ietf.org/html/rfc4253#section-4.2
            var buffer = new byte[255];
            var dummy = new byte[255];
            var pos = 0;

            while (pos < buffer.Length)
            {
                if (!WaitForSocket(SelectMode.SelectRead))
                    throw new SshConnectionException("Could't read the protocal version", DisconnectReason.ProtocolError);

                int len;
                try
                {
                    len = _socket.Receive(buffer, pos, buffer.Length - pos, SocketFlags.Peek);
                }
                catch (SocketException exp) when (
                    exp.SocketErrorCode == SocketError.WouldBlock ||
                    exp.SocketErrorCode == SocketError.IOPending ||
                    exp.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                {
                    continue;
                }
                catch (SocketException exp) when (
                    exp.SocketErrorCode == SocketError.ConnectionReset ||
                    exp.SocketErrorCode == SocketError.ConnectionAborted ||
                    exp.SocketErrorCode == SocketError.Shutdown)
                {
                    throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                }
                if (len == 0)
                {
                    throw new SshConnectionException("Could't read the protocal version", DisconnectReason.ProtocolError);
                }

                for (var i = 0; i < len; i++, pos++)
                {
                    if (pos > 0 && buffer[pos - 1] == CarriageReturn && buffer[pos] == LineFeed)
                    {
                        _socket.Receive(dummy, 0, i + 1, SocketFlags.None);
                        return Encoding.ASCII.GetString(buffer, 0, pos - 1);
                    }
                    else if (pos > 0 && buffer[pos] == LineFeed) // Non-RFC case
                    {
                        _socket.Receive(dummy, 0, i + 1, SocketFlags.None);
                        return Encoding.ASCII.GetString(buffer, 0, pos);
                    }
                }
                _socket.Receive(dummy, 0, len, SocketFlags.None);
            }
            throw new SshConnectionException("Could't read the protocal version", DisconnectReason.ProtocolError);
        }

        private void SocketWriteProtocolVersion()
        {
            SocketWrite(Encoding.ASCII.GetBytes(ServerVersion + "\r\n"));
        }

        /// <summary>
        /// A pooled receive buffer rented from <see cref="ArrayPool{byte}.Shared"/>
        /// by <see cref="SocketRead"/> and returned on Dispose. Callers must
        /// <c>using</c> the result and consume the bytes before disposing —
        /// the exposed <see cref="Span"/>/<see cref="Memory"/> views are valid
        /// only until Dispose returns the rental to the pool.
        ///
        /// Replaces the per-packet <c>new byte[length]</c> that previously
        /// backed every SocketRead call. The pool gives us a buffer that may
        /// be larger than <see cref="Length"/>; consumers must slice through
        /// <see cref="Span"/>/<see cref="Memory"/>, NOT index <see cref="Buffer"/>
        /// past <see cref="Length"/>.
        /// </summary>
        private ref struct PooledReceiveBuffer
        {
            private byte[] _buffer;
            private readonly int _length;

            public PooledReceiveBuffer(byte[] buffer, int length)
            {
                _buffer = buffer;
                _length = length;
            }

            public int Length => _length;
            public byte[] Buffer => _buffer ?? throw new ObjectDisposedException(nameof(PooledReceiveBuffer));
            public Span<byte> Span => _buffer.AsSpan(0, _length);
            public ReadOnlySpan<byte> ReadOnlySpan => _buffer.AsSpan(0, _length);
            public Memory<byte> Memory => _buffer.AsMemory(0, _length);
            public ReadOnlyMemory<byte> ReadOnlyMemory => _buffer.AsMemory(0, _length);

            /// <summary>
            /// Slice the pooled buffer without copying. Valid only until Dispose.
            /// </summary>
            public ReadOnlySpan<byte> Slice(int start, int length) => _buffer.AsSpan(start, length);

            public void Dispose()
            {
                if (_buffer != null)
                {
                    ArrayPool<byte>.Shared.Return(_buffer);
                    _buffer = null!;
                }
            }
        }

        /// <summary>
        /// Read exactly <paramref name="length"/> bytes from the socket into a
        /// pooled buffer (ArrayPool<byte>.Shared). Returns a ref struct that
        /// returns the rental on Dispose — callers MUST <c>using</c> the result
        /// and consume the bytes before disposing. The pooled buffer may be
        /// larger than <paramref name="length"/>; consume via the returned
        /// Span/Memory views, not by indexing Buffer past Length.
        ///
        /// Replaces the previous <c>new byte[length]</c> per call. On the SSH
        /// receive hot path this cuts one allocation per SocketRead call —
        /// AEAD: 2 calls (len + ciphertext), ETM: 3 calls, non-ETM: 4 calls
        /// per packet — all now pooled rather than GC'd.
        /// </summary>
        private PooledReceiveBuffer SocketRead(int length)
        {
            if (length < 0 || length > MaximumPacketLength + 4 + 64)
            {
                throw new SshConnectionException(
                    string.Format("Invalid read length {0}.", length),
                    DisconnectReason.ProtocolError);
            }

            var buffer = ArrayPool<byte>.Shared.Rent(length);
            var pos = 0;

            while (pos < length)
            {
                if (!WaitForSocket(SelectMode.SelectRead))
                    throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);

                int len;
                try
                {
                    len = _socket.Receive(buffer, pos, length - pos, SocketFlags.None);
                }
                catch (SocketException exp) when (
                    exp.SocketErrorCode == SocketError.WouldBlock ||
                    exp.SocketErrorCode == SocketError.IOPending ||
                    exp.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                {
                    continue;
                }
                catch (SocketException exp) when (
                    exp.SocketErrorCode == SocketError.ConnectionReset ||
                    exp.SocketErrorCode == SocketError.ConnectionAborted ||
                    exp.SocketErrorCode == SocketError.Shutdown)
                {
                    // Peer closed or reset the connection (e.g. normal exit after
                    // our channel/session teardown). Treat as a clean ConnectionLost,
                    // not an unexpected protocol error.
                    throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                }

                if (len == 0)
                    throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);

                pos += len;
            }

            return new PooledReceiveBuffer(buffer, length);
        }

        private void SocketWrite(ReadOnlySpan<byte> data)
        {
            var pos = 0;
            var length = data.Length;

            while (pos < length)
            {
                if (!WaitForSocket(SelectMode.SelectWrite))
                    throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);

                int sent;
                try
                {
                    sent = _socket.Send(data.Slice(pos, length - pos));
                }
                catch (SocketException ex) when (
                    ex.SocketErrorCode == SocketError.WouldBlock ||
                    ex.SocketErrorCode == SocketError.IOPending ||
                    ex.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                {
                    continue;
                }
                catch (SocketException ex) when (
                    ex.SocketErrorCode == SocketError.ConnectionReset ||
                    ex.SocketErrorCode == SocketError.ConnectionAborted ||
                    ex.SocketErrorCode == SocketError.Shutdown)
                {
                    throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                }

                if (sent == 0)
                    throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);

                pos += sent;
            }
        }

        private bool WaitForSocket(SelectMode mode)
        {
            // Non-blocking wait before Receive/Send so the I/O thread never spins or
            // sleeps on the socket. Poll takes microseconds; clamp the (debug) timeout
            // to int.MaxValue so a very large value cannot overflow the argument.
            var microSeconds = _timeout.TotalMilliseconds >= int.MaxValue / 1000d
                ? int.MaxValue
                : (int)(_timeout.TotalMilliseconds * 1000);
            return _socket.Poll(microSeconds, mode);
        }
        #endregion

        #region Message operations
        private Message ReceiveMessage()
        {
            var useAlg = _algorithms != null;
            var isEtm = useAlg && _algorithms.ClientHmacIsEtm;
            var isAead = useAlg && _algorithms.ClientEncryption.IsAead;

            // AEAD (RFC 5647 section 3): layout [packet_length(4, plaintext)][ciphertext][tag(16)].
            // packet_length is plaintext (same as ETM) but covers only the
            // ciphertext portion — NOT the tag. The GCM tag replaces the HMAC
            // and authenticates the ciphertext (the plaintext length field is
            // validated separately as bounded by MaximumPacketLength).
            if (isAead)
            {
                // lenBuf is the 4-byte plaintext packet_length that GCM uses
                // as Additional Authenticated Data. Dispose after DecryptAead
                // consumes it.
                using var lenBuf = SocketRead(4);
                var lenSpan = lenBuf.Span;
                var packetLength = lenSpan[0] << 24 | lenSpan[1] << 16 | lenSpan[2] << 8 | lenSpan[3];
                if (packetLength < MinimumPacketLength || packetLength > MaximumPacketLength)
                {
                    throw new SshConnectionException(
                        string.Format("Invalid packet length {0}. Must be between {1} and {2}.",
                            (uint)packetLength, MinimumPacketLength, MaximumPacketLength),
                        DisconnectReason.ProtocolError);
                }

                // packetLength bytes of ciphertext: padding_length || payload || padding,
                // followed by the 16-byte GCM tag. Per RFC 5647 section 7.3 the 4-byte
                // plaintext packet_length (lenBuf) is GCM's Additional Authenticated
                // Data -- authenticated but not encrypted, covered by the tag.
                var tagLength = _algorithms.ClientEncryption.TagBytes;
                using var ciphertextWithTag = SocketRead(packetLength + tagLength);

                // Decrypt straight into a pooled buffer (the plaintext is exactly
                // packetLength bytes). The rental is returned in finally after
                // Decompress has copied the payload out, so the receive path
                // allocates no plaintext array per packet.
                var plaintext = ArrayPool<byte>.Shared.Rent(packetLength);
                try
                {
                    // AAD is exactly the 4-byte plaintext packet_length --
                    // NOT the whole lenBuf rental (ArrayPool hands back at
                    // least 16 bytes; OpenSSH authenticates exactly 4).
                    _algorithms.ClientEncryption.DecryptAead(
                        lenBuf.ReadOnlySpan,
                        ciphertextWithTag.Buffer.AsSpan(0, packetLength + tagLength),
                        plaintext);

                    var paddingLength = plaintext[0];
                    var dataLength = packetLength - paddingLength - 1;
                    var data = plaintext.AsMemory(1, dataLength);
                    var dataArray = _algorithms.ClientCompression.Decompress(data).ToArray();

                    return LoadMessage(dataArray[0], dataArray, packetLength);
                }
                catch (CryptographicException)
                {
                    // GCM tag mismatch is the AEAD equivalent of an HMAC failure --
                    // RFC 4253 section 6.4 mandates connection termination with MAC_ERROR.
                    throw new SshConnectionException("Invalid AEAD tag", DisconnectReason.MacError);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(plaintext);
                }
            }

            // OpenSSH Encrypt-then-MAC (RFC 6668): packet_length is NOT encrypted.
            // Layout: [length(4, plaintext)][encrypt(padding_length||payload||padding)][MAC].
            if (isEtm)
            {
                using var lenBuf = SocketRead(4);
                var lenSpan = lenBuf.Span;
                var packetLength = lenSpan[0] << 24 | lenSpan[1] << 16 | lenSpan[2] << 8 | lenSpan[3];
                if (packetLength < MinimumPacketLength || packetLength > MaximumPacketLength)
                {
                    throw new SshConnectionException(
                        string.Format("Invalid packet length {0}. Must be between {1} and {2}.",
                            (uint)packetLength, MinimumPacketLength, MaximumPacketLength),
                        DisconnectReason.ProtocolError);
                }

                // packetLength bytes of ciphertext: padding_length || payload || padding.
                using var cipher = SocketRead(packetLength);
                var encryptedSpan = cipher.ReadOnlySpan;

                // clientMacBuf is disposed right after the SequenceEqual
                // comparison, before we touch the cipher buffer again.
                using var clientMacBuf = SocketRead(_algorithms.ClientHmac.DigestLength);
                Span<byte> mac = stackalloc byte[_algorithms.ClientHmac.DigestLength];
                ComputeHmac(_algorithms.ClientHmac, lenBuf.ReadOnlySpan, encryptedSpan, _inboundPacketSequence, mac);
                if (!clientMacBuf.Span.SequenceEqual(mac))
                {
                    throw new SshConnectionException("Invalid MAC", DisconnectReason.MacError);
                }

                // Transform exactly packetLength bytes: the buffer is an
                // ArrayPool rental that may be larger than the packet, and
                // the CTR keystream counter advances by the transform length -
                // over-advancing would corrupt every subsequent packet.
                _algorithms.ClientEncryption.Transform(cipher.Buffer, packetLength, cipher.Buffer);
                var paddingLength = cipher.Span[0];
                var dataLength = packetLength - paddingLength - 1;
                var data = cipher.Memory.Slice(1, dataLength);
                var dataArray = _algorithms.ClientCompression.Decompress(data).ToArray();

                return LoadMessage(dataArray[0], dataArray, packetLength);
            }

            var blockSize = (byte)(useAlg ? Math.Max(8, _algorithms.ClientEncryption.BlockBytesSize) : 8);
            using var rawFirst = SocketRead(blockSize);
            if (useAlg)
                _algorithms.ClientEncryption.Transform(rawFirst.Buffer, blockSize, rawFirst.Buffer);

            var rawFirstSpan = rawFirst.Span;
            var packetLengthNonEtm = rawFirstSpan[0] << 24 | rawFirstSpan[1] << 16 | rawFirstSpan[2] << 8 | rawFirstSpan[3];
            if (packetLengthNonEtm < MinimumPacketLength || packetLengthNonEtm > MaximumPacketLength)
            {
                throw new SshConnectionException(
                    string.Format("Invalid packet length {0}. Must be between {1} and {2}.",
                        (uint)packetLengthNonEtm, MinimumPacketLength, MaximumPacketLength),
                        DisconnectReason.ProtocolError);
            }

            var paddingLengthNonEtm = rawFirstSpan[4];
            var bytesToRead = packetLengthNonEtm - blockSize + 4;

            using var followingBlocks = SocketRead(bytesToRead);
            if (useAlg && followingBlocks.Length > 0)
                _algorithms.ClientEncryption.Transform(followingBlocks.Buffer, bytesToRead, followingBlocks.Buffer);

            // RFC 4253 section 6: payload length = packet_length - padding_length - 1
            // (the -1 is the padding_length byte itself). The AEAD/ETM paths
            // above compute the same with - 1; omitting it here would leave a
            // trailing padding byte in every message, breaking byte-exact
            // consumers (public-key signature verification data).
            var dataLengthNonEtm = packetLengthNonEtm - paddingLengthNonEtm - 1;
            var dataNonEtm = new byte[dataLengthNonEtm];
            var fromFirst = Math.Min(dataLengthNonEtm, blockSize - 5);
            if (fromFirst > 0)
                rawFirst.Span.Slice(5, fromFirst).CopyTo(dataNonEtm);
            followingBlocks.Span.Slice(0, dataLengthNonEtm - fromFirst).CopyTo(dataNonEtm.AsSpan(fromFirst));

            if (useAlg)
            {
                // clientMacBuf is disposed after the SequenceEqual comparison,
                // before we re-read the cipher for Decompress.
                using var clientMacBuf = SocketRead(_algorithms.ClientHmac.DigestLength);
                Span<byte> mac = stackalloc byte[_algorithms.ClientHmac.DigestLength];
                ComputeHmac(_algorithms.ClientHmac, rawFirst.ReadOnlySpan, followingBlocks.ReadOnlySpan, _inboundPacketSequence, mac);
                if (!clientMacBuf.Span.SequenceEqual(mac))
                {
                    throw new SshConnectionException("Invalid MAC", DisconnectReason.MacError);
                }

                dataNonEtm = _algorithms.ClientCompression.Decompress(dataNonEtm).ToArray();
            }

            var typeNumber = dataNonEtm[0];
            return LoadMessage(typeNumber, dataNonEtm, packetLengthNonEtm);
        }

        /// <summary>
        /// Convert a decrypted payload into a Message instance, then update
        /// inbound sequencing and the keepalive idle clock. Shared by the ETM
        /// and the regular receive paths.
        /// </summary>
        private Message LoadMessage(byte typeNumber, byte[] data, int packetLength)
        {
            if (Log.IsEnabled(LogLevel.Trace))
            {
                var implemented0 = _messagesMetadata.ContainsKey(typeNumber);
                Log.Trace(implemented0
                    ? $"Recv msg={_messagesMetadata[typeNumber].Name} len={packetLength} seq={_inboundPacketSequence}"
                    : $"Recv msg=Unknown({typeNumber}) len={packetLength} seq={_inboundPacketSequence}");
            }

            var implemented = _messagesMetadata.ContainsKey(typeNumber);
            var message = implemented
                ? (Message)Activator.CreateInstance(_messagesMetadata[typeNumber])
                : new UnknownMessage { SequenceNumber = _inboundPacketSequence, UnknownMessageType = typeNumber };

            if (implemented)
                message.Load(data);

            lock (_locker)
            {
                _inboundPacketSequence++;
                _inboundFlow += (uint)packetLength;
            }

            ConsiderReExchange();

            // Any inbound frame proves the link is alive; refresh the keepalive
            // idle clock so probing does not fire while the peer is active.
            _lastActivity?.Restart();

            return message;
        }

        internal void SendMessage(Message message)
        {
            ArgumentNullException.ThrowIfNull(message);

            if (_exchangeContext != null
                && message.MessageType > 4 && (message.MessageType < 20 || message.MessageType > 49))
            {
                _blockedMessages.Enqueue(message);
                return;
            }

            _hasBlockedMessagesWaitHandle.WaitOne();
            lock (_locker)
                SendMessageInternal(message);
        }

        private void SendMessageInternal(Message message)
        {
            var useAlg = _algorithms != null;
            var isAead = useAlg && _algorithms.ServerEncryption.IsAead;
            // The "none" compression hot path (the bulk forwarding case) is an
            // identity transform: writing the message payload straight into a
            // pooled writer skips the intermediate byte[] that
            // message.GetPacket() would allocate. Only a real compressor (which
            // returns its own byte[]) produces a standalone payload array.
            var identityCompression = useAlg && _algorithms.ServerCompression.IsIdentity;

            var blockSize = (byte)(useAlg ? Math.Max(8, _algorithms.ServerEncryption.BlockBytesSize) : 8);

            SshDataWriter payloadWriter = null;
            byte[] payload = null;
            int payloadLength;
            if (useAlg && !identityCompression)
            {
                // Compressor returns a byte[]; keep that array as the payload.
                payload = _algorithms.ServerCompression.Compress(message.GetPacket());
                payloadLength = payload.Length;
            }
            else
            {
                payloadWriter = new SshDataWriter();
                message.WritePayload(payloadWriter);
                payloadLength = payloadWriter.Length;
            }

            // http://tools.ietf.org/html/rfc4253
            // 6.  Binary Packet Protocol
            // the total length of (packet_length || padding_length || payload || padding)
            // is a multiple of the cipher block size or 8,
            // padding length must between 4 and 255 bytes.
            //
            // OpenSSH ETM (RFC 6668) and AEAD (RFC 5647) both transmit
            // packet_length in plaintext and the peer validates it immediately,
            // so the padding must make packet_length itself a multiple of the
            // block size (packet_length = payload.Length + padding + 1).
            byte paddingLength;
            if (useAlg && (_algorithms.ServerHmacIsEtm || isAead))
            {
                paddingLength = (byte)(blockSize - (payloadLength + 1) % blockSize);
                if (paddingLength < 4)
                    paddingLength += blockSize;
            }
            else
            {
                paddingLength = (byte)(blockSize - (payloadLength + 5) % blockSize);
                if (paddingLength < 4)
                    paddingLength += blockSize;
            }

            var packetLength = (uint)payloadLength + paddingLength + 1;

            // Frame the packet straight into the session's reusable plaintext
            // buffer: [packet_length(4)][padding_length(1)][payload][padding].
            // No per-packet frame array, no padding array, no ToByteArray —
            // the frame lives in _sendScratchBuffer for the duration of the
            // (serialized) send, then is overwritten by the next packet.
            var framedLength = 4 + (int)packetLength;
            var frame = _sendScratchBuffer.AsSpan(0, framedLength);
            frame[0] = (byte)(packetLength >> 24);
            frame[1] = (byte)(packetLength >> 16);
            frame[2] = (byte)(packetLength >> 8);
            frame[3] = (byte)packetLength;
            frame[4] = paddingLength;
            if (payload != null)
                payload.AsSpan().CopyTo(frame.Slice(5));
            else
                // Copy the pooled writer's bytes into the frame; TryWriteTo
                // also returns the writer's rental to the pool, so subsequent
                // Dispose is a no-op.
                payloadWriter.TryWriteTo(frame.Slice(5));
            RandomNumberGenerator.Fill(frame.Slice(5 + payloadLength, paddingLength));

            payloadWriter?.Dispose();

            ReadOnlySpan<byte> wire;
            if (useAlg)
            {
                if (isAead)
                {
                    // RFC 5647 section 3 + 7.3 AEAD layout:
                    // [packet_length(4, plaintext)][ciphertext = encrypt(padding_length||payload||padding)][tag(16)].
                    // The 4-byte plaintext packet_length is GCM's AAD
                    // (authenticated but not encrypted). Encrypt straight into
                    // the reusable _sendBuffer — no intermediate ciphertext
                    // array per packet.
                    var tagBytes = _algorithms.ServerEncryption.TagBytes;
                    var cipherLen = framedLength - 4;
                    var packet = _sendBuffer.AsSpan(0, 4 + cipherLen + tagBytes);
                    frame.Slice(0, 4).CopyTo(packet);
                    _algorithms.ServerEncryption.EncryptAead(
                        frame.Slice(0, 4),
                        frame.Slice(4),
                        packet.Slice(4));
                    wire = packet;
                }
                else if (_algorithms.ServerHmacIsEtm)
                {
                    // OpenSSH Encrypt-then-MAC (RFC 6668): packet_length is NOT
                    // encrypted. Layout: [length(4, plaintext)][encrypt(padding_length||payload||padding)][MAC].
                    // MAC covers seq || length || ciphertext.
                    // Encrypt the body in place inside the scratch buffer
                    // (frame[4..] becomes ciphertext), compute the MAC into
                    // stackalloc, then assemble the wire packet in the reusable
                    // _sendBuffer — no per-packet arrays.
                    var macLength = _algorithms.ServerHmac.DigestLength;
                    var cipherLen = framedLength - 4;
                    _algorithms.ServerEncryption.Transform(_sendScratchBuffer, 4, cipherLen, _sendScratchBuffer, 4);

                    Span<byte> mac = stackalloc byte[macLength];
                    ComputeHmac(_algorithms.ServerHmac, frame.Slice(0, 4), frame.Slice(4, cipherLen), _outboundPacketSequence, mac);

                    var packet = _sendBuffer.AsSpan(0, 4 + cipherLen + macLength);
                    frame.Slice(0, 4 + cipherLen).CopyTo(packet);
                    mac.CopyTo(packet.Slice(4 + cipherLen));
                    wire = packet;
                }
                else
                {
                    // RFC 4253: the whole packet is encrypted; MAC covers the plaintext.
                    var macLength = _algorithms.ServerHmac.DigestLength;
                    var encrypted = _sendBuffer.AsSpan(0, framedLength + macLength);
                    _algorithms.ServerEncryption.Transform(_sendScratchBuffer, framedLength, _sendBuffer);
                    Span<byte> mac = stackalloc byte[macLength];
                    ComputeHmac(_algorithms.ServerHmac, frame, ReadOnlySpan<byte>.Empty, _outboundPacketSequence, mac);
                    mac.CopyTo(encrypted.Slice(framedLength));
                    wire = encrypted;
                }
            }
            else
            {
                // Pre-KEX: no encryption; the plaintext frame goes out as-is.
                wire = frame;
            }

            SocketWrite(wire);

            if (Log.IsEnabled(LogLevel.Trace))
            {
                Log.Trace($"Sent msg={message.GetType().Name} seq={_outboundPacketSequence}");
            }

            lock (_locker)
            {
                _outboundPacketSequence++;
                _outboundFlow += packetLength;
            }

            ConsiderReExchange();

            // Outbound traffic also proves the link is alive (and advances the
            // peer's ACK), so it counts toward keepalive idle resetting.
            _lastActivity?.Restart();
        }

        private void ConsiderReExchange(bool force = false)
        {
            var kex = false;
            lock (_locker)
                if (_exchangeContext == null
                    && (force || _inboundFlow + _outboundFlow > 1024 * 1024 * 512)) // 0.5 GiB
                {
                    _exchangeContext = new ExchangeContext();
                    kex = true;
                }

            if (kex)
            {
                Log.Debug(force ? "Key exchange triggered (forced)."
                    : "Key exchange triggered (traffic threshold reached).");
                var kexInitMessage = LoadKexInitMessage();
                _exchangeContext.ServerKexInitPayload = kexInitMessage.GetPacket();

                SendMessage(kexInitMessage);
            }
        }

        private void ContinueSendBlockedMessages()
        {
            if (_blockedMessages.Count > 0)
            {
                Message message;
                while (_blockedMessages.TryDequeue(out message))
                {
                    SendMessageInternal(message);
                }
            }
        }

        internal bool TrySendMessage(Message message)
        {
            ArgumentNullException.ThrowIfNull(message);

            try
            {
                SendMessage(message);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private Message LoadKexInitMessage()
        {
            // RFC 8308: advertise "ext-info-s" inside the kex_algorithms
            // name-list so the client knows we accept SSH_MSG_EXT_INFO.
            var kexAlgs = new List<string>(_keyExchangeAlgorithms.Keys) { "ext-info-s" };

            var message = new KeyExchangeInitMessage
            {
                KeyExchangeAlgorithms = kexAlgs.ToArray(),
                ServerHostKeyAlgorithms = _publicKeyAlgorithms.Keys.Intersect(_hostKey.Keys).ToArray(),
                EncryptionAlgorithmsClientToServer = [.. _encryptionAlgorithms.Keys],
                EncryptionAlgorithmsServerToClient = [.. _encryptionAlgorithms.Keys],
                MacAlgorithmsClientToServer = [.. _hmacAlgorithms.Keys],
                MacAlgorithmsServerToClient = [.. _hmacAlgorithms.Keys],
                CompressionAlgorithmsClientToServer = [.. _compressionAlgorithms.Keys],
                CompressionAlgorithmsServerToClient = [.. _compressionAlgorithms.Keys],
                LanguagesClientToServer = [""],
                LanguagesServerToClient = [""],
                FirstKexPacketFollows = false,
                Reserved = 0,
            };

            return message;
        }
        #endregion

        #region Handle messages
        private void HandleMessageCore(Message message)
        {
            this.HandleMessage((dynamic)message);
        }

        private void HandleMessage(DisconnectMessage message)
        {
            Disconnect(message.ReasonCode, message.Description);
        }

        private void HandleMessage(KeyExchangeInitMessage message)
        {
            ConsiderReExchange(true);

            KeysExchanged?.Invoke(this, new KeyExchangeArgs(this)
            {
                CompressionAlgorithmsClientToServer = message.CompressionAlgorithmsClientToServer,
                CompressionAlgorithmsServerToClient = message.CompressionAlgorithmsServerToClient,
                EncryptionAlgorithmsClientToServer = message.EncryptionAlgorithmsClientToServer,
                EncryptionAlgorithmsServerToClient = message.EncryptionAlgorithmsServerToClient,
                KeyExchangeAlgorithms = message.KeyExchangeAlgorithms,
                LanguagesClientToServer = message.LanguagesClientToServer,
                LanguagesServerToClient = message.LanguagesServerToClient,
                MacAlgorithmsClientToServer = message.MacAlgorithmsClientToServer,
                MacAlgorithmsServerToClient = message.MacAlgorithmsServerToClient,
                ServerHostKeyAlgorithms = message.ServerHostKeyAlgorithms
            });

            _exchangeContext.KeyExchange = ChooseAlgorithm([.. _keyExchangeAlgorithms.Keys], message.KeyExchangeAlgorithms);
            _exchangeContext.PublicKey = ChooseAlgorithm(_publicKeyAlgorithms.Keys.Intersect(_hostKey.Keys).ToArray(), message.ServerHostKeyAlgorithms);
            _exchangeContext.ClientEncryption = ChooseAlgorithm([.. _encryptionAlgorithms.Keys], message.EncryptionAlgorithmsClientToServer);
            _exchangeContext.ServerEncryption = ChooseAlgorithm([.. _encryptionAlgorithms.Keys], message.EncryptionAlgorithmsServerToClient);
            _exchangeContext.ClientHmac = ChooseAlgorithm([.. _hmacAlgorithms.Keys], message.MacAlgorithmsClientToServer);
            _exchangeContext.ServerHmac = ChooseAlgorithm([.. _hmacAlgorithms.Keys], message.MacAlgorithmsServerToClient);
            _exchangeContext.ClientCompression = ChooseAlgorithm([.. _compressionAlgorithms.Keys], message.CompressionAlgorithmsClientToServer);
            _exchangeContext.ServerCompression = ChooseAlgorithm([.. _compressionAlgorithms.Keys], message.CompressionAlgorithmsServerToClient);

            _exchangeContext.ClientKexInitPayload = message.GetPacket();

            Log.Info($"Negotiated: kex={_exchangeContext.KeyExchange}, hostkey={_exchangeContext.PublicKey}, " +
                $"ctos={_exchangeContext.ClientEncryption}:{_exchangeContext.ClientHmac}:{_exchangeContext.ClientCompression}, " +
                $"stoc={_exchangeContext.ServerEncryption}:{_exchangeContext.ServerHmac}:{_exchangeContext.ServerCompression}.");

            // RFC 8308: remember whether the client supports EXT_INFO.
            _clientAdvertisedExtInfo = message.PeerExtensions.Contains("ext-info-c");
        }

        private void HandleMessage(KeyExchangeXInitMessage message)
        {
            switch (_exchangeContext.PublicKey)
            {
                case "rsa-sha2-256":
                case "rsa-sha2-512":
                    message = Message.LoadFrom<KeyExchangeDhInitMessage>(message);
                    break;
                case "ecdsa-sha2-nistp256":
                case "ecdsa-sha2-nistp384":
                case "ecdsa-sha2-nistp521":
                    message = Message.LoadFrom<KeyExchangeECDhInitMessage>(message);
                    break;
                default:
                    throw new InvalidOperationException();
            }
            HandleMessageCore(message);
        }

        private void HandleMessage(KeyExchangeDhInitMessage message)
        {
            var kexAlg = _keyExchangeAlgorithms[_exchangeContext.KeyExchange]();
            var hostKeyAlg = _publicKeyAlgorithms[_exchangeContext.PublicKey](_hostKey[_exchangeContext.PublicKey]);
            var clientCipher = _encryptionAlgorithms[_exchangeContext.ClientEncryption]();
            var serverCipher = _encryptionAlgorithms[_exchangeContext.ServerEncryption]();
            var serverHmac = _hmacAlgorithms[_exchangeContext.ServerHmac]();
            var clientHmac = _hmacAlgorithms[_exchangeContext.ClientHmac]();

            var clientExchangeValue = message.E;
            var serverExchangeValue = kexAlg.CreateKeyExchange();
            var sharedSecret = kexAlg.DecryptKeyExchange(clientExchangeValue);
            var hostKeyAndCerts = hostKeyAlg.CreateKeyAndCertificatesData();
            var exchangeHash = ComputeExchangeHash(kexAlg, hostKeyAndCerts, clientExchangeValue, serverExchangeValue, sharedSecret, false);

            if (SessionId == null)
            {
                SessionId = exchangeHash;
                Log.Info($"Key exchange complete, session id {BitConverter.ToString(exchangeHash).Replace("-", "").Substring(0, 16)}…");
            }

            _exchangeContext.NewAlgorithms = ComputeEncryption(kexAlg, hostKeyAlg, exchangeHash, clientCipher, serverCipher, clientHmac, serverHmac, sharedSecret);

            var reply = new KeyExchangeDhReplyMessage
            {
                HostKey = hostKeyAndCerts,
                F = serverExchangeValue,
                Signature = hostKeyAlg.CreateSignatureData(exchangeHash),
            };

            SendMessage(reply);
        }

        private void HandleMessage(KeyExchangeECDhInitMessage message)
        {
            var kexAlg = _keyExchangeAlgorithms[_exchangeContext.KeyExchange]();
            var hostKeyAlg = _publicKeyAlgorithms[_exchangeContext.PublicKey](_hostKey[_exchangeContext.PublicKey]);
            var clientCipher = _encryptionAlgorithms[_exchangeContext.ClientEncryption]();
            var serverCipher = _encryptionAlgorithms[_exchangeContext.ServerEncryption]();
            var serverHmac = _hmacAlgorithms[_exchangeContext.ServerHmac]();
            var clientHmac = _hmacAlgorithms[_exchangeContext.ClientHmac]();

            var clientExchangeValue = message.Q;
            var serverExchangeValue = kexAlg.CreateKeyExchange();
            var sharedSecret = kexAlg.DecryptKeyExchange(clientExchangeValue);
            var hostKeyAndCerts = hostKeyAlg.CreateKeyAndCertificatesData();
            var exchangeHash = ComputeExchangeHash(kexAlg, hostKeyAndCerts, clientExchangeValue, serverExchangeValue, sharedSecret, true);

            if (SessionId == null)
            {
                SessionId = exchangeHash;
                Log.Info($"Key exchange complete, session id {BitConverter.ToString(exchangeHash).Replace("-", "").Substring(0, 16)}…");
            }

            _exchangeContext.NewAlgorithms = ComputeEncryption(kexAlg, hostKeyAlg, exchangeHash, clientCipher, serverCipher, clientHmac, serverHmac, sharedSecret);

            var reply = new KeyExchangeECDhReplyMessage
            {
                HostKey = hostKeyAndCerts,
                Q = serverExchangeValue,
                Signature = hostKeyAlg.CreateSignatureData(exchangeHash),
            };

            SendMessage(reply);
        }

        private void HandleMessage(NewKeysMessage message)
        {
            // RFC 4253 7.3: send SSH_MSG_NEWKEYS before applying the new keys.
            // We deliberately send the server's NEWKEYS here (after receiving the
            // client's NEWKEYS) so that our server's NEWKEYS data segment piggybacks
            // the ACK for the client's NEWKEYS. Otherwise the client's NEWKEYS stays
            // un-ACKed and Nagle blocks the subsequent SERVICE_REQUEST until the
            // delayed-ACK timer fires (~40ms on Linux).
            Log.Debug("New keys applied.");
            SendMessageInternal(new NewKeysMessage());

            _hasBlockedMessagesWaitHandle.Reset();

            lock (_locker)
            {
                _inboundFlow = 0;
                _outboundFlow = 0;
                _algorithms = _exchangeContext.NewAlgorithms;
                _exchangeContext = null;
            }

            // RFC 8308 section 2.2: send SSH_MSG_EXT_INFO as the first message
            // under the new keys, before any blocked messages are flushed.
            // Only send when the client advertised "ext-info-c" in its KEXINIT.
            if (_clientAdvertisedExtInfo && _extensionsToSend.Count > 0)
            {
                SendMessageInternal(new ExtInfoMessage
                {
                    Extensions = new Dictionary<string, string>(_extensionsToSend)
                });
            }

            ContinueSendBlockedMessages();
            _hasBlockedMessagesWaitHandle.Set();
        }

        /// <summary>
        /// Register a protocol extension to advertise via SSH_MSG_EXT_INFO
        /// (RFC 8308). Call before the first connection is accepted, or at
        /// session setup. Extensions are sent immediately after NEWKEYS
        /// during each key exchange when the peer supports ext-info-c.
        /// </summary>
        /// <param name="name">Extension name (e.g. "server-sig-algs").</param>
        /// <param name="value">Extension value (e.g. "ssh-ed25519,rsa-sha2-512").</param>
        public void RegisterExtension(string name, string value)
        {
            _extensionsToSend[name] = value;
        }

        private void HandleMessage(ExtInfoMessage message)
        {
            // RFC 8308 section 2.2: the client sends SSH_MSG_EXT_INFO
            // right after its NEWKEYS. We do not currently define any
            // client-to-server extensions to act on; acknowledging receipt
            // is sufficient for protocol correctness and future compatibility.
        }

        private void HandleMessage(UnimplementedMessage message)
        {
            // Nothing to do here
        }

        private void HandleMessage(GlobalRequestMessage message)
        {
            // SSH_MSG_GLOBAL_REQUEST (RFC 4254 section 4) can arrive at any
            // time, even before ssh-connection is registered, so we handle it
            // here at the session level rather than forwarding to ConnectionService.
            switch (message.RequestName)
            {
                case "keepalive@openssh.com":
                    // OpenSSH keepalive: no payload, just probe liveness.
                    // Reply SUCCESS when the peer asks for a reply; keep silent
                    // otherwise (want-reply=false is a one-way probe).
                    if (message.WantReply)
                        SendMessage(new RequestSuccessMessage());
                    break;
                default:
                    // Business-related global requests (tcpip-forward, etc.)
                    // belong to the connection service. Forward when registered.
                    // If not registered yet, reply FAILURE per RFC 4254.
                    var conn = GetService<ConnectionService>();
                    if (conn != null)
                    {
                        conn.HandleMessage(message);
                    }
                    else if (message.WantReply)
                    {
                        SendMessage(new RequestFailureMessage());
                    }
                    break;
            }
        }

        private void HandleMessage(RequestSuccessMessage message)
        {
            // SSH_MSG_REQUEST_SUCCESS (RFC 4254 section 4): a peer honoured our
            // keepalive probe. Both SUCCESS and FAILURE prove liveness, so clear
            // the missed-probe counter. The activity clock itself is already
            // refreshed in ReceiveMessage, the single inbound entry point.
            Interlocked.Exchange(ref _missedProbes, 0);
        }

        private void HandleMessage(RequestFailureMessage message)
        {
            // SSH_MSG_REQUEST_FAILURE (RFC 4254 section 4): a peer rejected our
            // global request. For keepalive this still proves liveness, so we
            // do not treat it as an error; same counter reset as for SUCCESS.
            Interlocked.Exchange(ref _missedProbes, 0);
        }

        /// <summary>
        /// Send a keepalive@openssh.com global request to the peer and ask for
        /// a reply. Use this from a server-side idle timer to detect dead
        /// connections before the TCP keepalive timeout fires. The peer's
        /// REQUEST_SUCCESS / REQUEST_FAILURE is handled by the corresponding
        /// HandleMessage overloads; both are treated as proof of liveness.
        /// </summary>
        public void SendGlobalKeepalive()
        {
            SendMessage(new GlobalRequestMessage
            {
                RequestName = "keepalive@openssh.com",
                WantReply = true,
            });
        }

        /// <summary>
        /// Enable or update server-side keepalive probing. After the session
        /// has been idle (no inbound or outbound traffic) for <paramref name="idle"/>,
        /// the server sends a keepalive@openssh.com global request every
        /// <paramref name="idle"/> interval. If the peer fails to answer
        /// MaxMissedProbes consecutive probes the session is torn down.
        /// Pass a non-positive value to disable probing. Calling this before
        /// the session is established is allowed; the timer starts immediately.
        /// </summary>
        public void ConfigureKeepalive(TimeSpan idle)
        {
            lock (_locker)
            {
                _keepaliveIdle = idle;

                if (idle <= TimeSpan.Zero)
                {
                    _keepaliveTimer?.Dispose();
                    _keepaliveTimer = null;
                    _missedProbes = 0;
                    Log.Debug("Keepalive probing disabled.");
                    return;
                }

                Log.Debug($"Keepalive probing enabled, idle threshold {idle}.");

                _lastActivity ??= Stopwatch.StartNew();

                // Period = idle: when idle has elapsed we start probing at the
                // same cadence. DueTime also idle so the first probe fires one
                // idle window after the last activity, not immediately.
                var due = (int)Math.Min(idle.TotalMilliseconds, int.MaxValue);
                if (_keepaliveTimer == null)
                    _keepaliveTimer = new Timer(KeepaliveTick, null, due, due);
                else
                    _keepaliveTimer.Change(due, due);
            }
        }

        private void KeepaliveTick(object state)
        {
            if (_disconnected || _socket == null)
                return;

            // Not idle long enough yet - peer is active, nothing to probe.
            if (_lastActivity?.Elapsed < _keepaliveIdle)
                return;

            // Idle window elapsed: probe and count. If the peer answers, the
            // RequestSuccess/Failure handler clears the counter; otherwise we
            // keep accumulating until MaxMissedProbes, then tear down.
            //
            // SendGlobalKeepalive() can block on WaitForSocket(Poll) for up to
            // the socket-receive timeout (30 s release, 1 d debug). During that
            // window another concurrent timer callback may have disconnected the
            // session via the MaxMissedProbes path and disposed the socket, causing
            // ObjectDisposedException when the blocking Poll finally completes.
            // Guard by re-checking _disconnected after the send returns, and
            // protect the send itself against the disposed-socket race.
            try
            {
                SendGlobalKeepalive();
            }
            catch (ObjectDisposedException)
            {
                // The socket was disposed by another concurrent callback that
                // already handled the disconnect - nothing more to do.
                return;
            }

            // Re-check: another concurrent callback may have disconnected us
            // while SendGlobalKeepalive was blocked on Poll. If so, our probe
            // went nowhere; do not count it.
            if (_disconnected)
                return;

            var missed = Interlocked.Increment(ref _missedProbes);
            if (missed >= MaxMissedProbes)
            {
                Log.Warn($"Keepalive probe unanswered {missed} times; disconnecting.");
                Disconnect(DisconnectReason.ByApplication, "Keepalive timeout.");
            }
            else
            {
                Log.Debug($"Keepalive probe {missed}/{MaxMissedProbes} unanswered.");
            }
        }

        private void HandleMessage(ServiceRequestMessage message)
        {
            SshService service = RegisterService(message.ServiceName);
            if (service != null)
            {
                SendMessage(new ServiceAcceptMessage(message.ServiceName));
                return;
            }
            throw new SshConnectionException(string.Format("Service \"{0}\" not available.", message.ServiceName),
                DisconnectReason.ServiceNotAvailable);
        }

        private void HandleMessage(UserAuthServiceMessage message)
        {
            var service = GetService<UserAuthService>();
            if (service != null)
                service.HandleMessageCore(message);
        }

        private void HandleMessage(ConnectionServiceMessage message)
        {
            var service = GetService<ConnectionService>();
            if (service != null)
                service.HandleMessageCore(message);
        }
        #endregion

        private string ChooseAlgorithm(string[] serverAlgorithms, string[] clientAlgorithms)
        {
            foreach (var client in clientAlgorithms)
                foreach (var server in serverAlgorithms)
                    if (client == server)
                        return client;

            throw new SshConnectionException("Failed to negotiate algorithm.", DisconnectReason.KeyExchangeFailed);
        }

        private byte[] ComputeExchangeHash(KexAlgorithm kexAlg, byte[] hostKeyAndCerts, byte[] clientExchangeValue, byte[] serverExchangeValue, byte[] sharedSecret, bool isEcdh)
        {
            var writer = new SshDataWriter(32 + ClientVersion.Length + ServerVersion.Length + _exchangeContext.ClientKexInitPayload.Length + _exchangeContext.ServerKexInitPayload.Length + hostKeyAndCerts.Length + clientExchangeValue.Length + serverExchangeValue.Length + sharedSecret.Length)
                .Write(ClientVersion, Encoding.ASCII)
                .Write(ServerVersion, Encoding.ASCII)
                .WriteBinary(_exchangeContext.ClientKexInitPayload)
                .WriteBinary(_exchangeContext.ServerKexInitPayload)
                .WriteBinary(hostKeyAndCerts);
            if (isEcdh)
            {
                writer.WriteBinary(clientExchangeValue);
                writer.WriteBinary(serverExchangeValue);
            }
            else
            {
                writer.WriteMpint(clientExchangeValue);
                writer.WriteMpint(serverExchangeValue);
            }
            writer.WriteMpint(sharedSecret);
            return kexAlg.ComputeHash(writer.ToByteArray());
        }

        private Algorithms ComputeEncryption(KexAlgorithm kexAlg, PublicKeyAlgorithm hostKeyAlg, byte[] exchangeHash, CipherInfo clientCipher, CipherInfo serverCipher, HmacInfo clientHmac, HmacInfo serverHmac, byte[] sharedSecret)
        {
            // IV length is algorithm-specific: AES-CBC/CTR use a full block (16
            // bytes), AES-GCM uses the 4-byte fixed_iv (RFC 5647 section 7.1). The
            // remaining 8 bytes of the GCM nonce are a per-packet counter owned
            // by GcmModeCryptoTransform.
            var clientCipherIV = ComputeEncryptionKey(kexAlg, exchangeHash, clientCipher.IVSize, sharedSecret, 'A');
            var serverCipherIV = ComputeEncryptionKey(kexAlg, exchangeHash, serverCipher.IVSize, sharedSecret, 'B');
            var clientCipherKey = ComputeEncryptionKey(kexAlg, exchangeHash, clientCipher.KeySize >> 3, sharedSecret, 'C');
            var serverCipherKey = ComputeEncryptionKey(kexAlg, exchangeHash, serverCipher.KeySize >> 3, sharedSecret, 'D');

            var clientEncryption = clientCipher.Cipher(clientCipherKey, clientCipherIV, false);
            var serverEncryption = serverCipher.Cipher(serverCipherKey, serverCipherIV, true);

            // AEAD (GCM) replaces the separate HMAC with an inline auth tag.
            // RFC 5647 section 6: the negotiated MAC name is still carried in KEX_INIT
            // and the MAC key is still derived for compatibility, but it MUST NOT
            // be used to authenticate packets — the GCM tag does that. We skip
            // deriving the MAC key for the AEAD direction entirely (nothing reads
            // ClientHmac/ServerHmac when the corresponding cipher IsAead), and
            // leave the HmacAlgorithm slots null so any accidental use fails loud.
            HmacAlgorithm clientHmacAlg = null;
            HmacAlgorithm serverHmacAlg = null;
            if (!clientEncryption.IsAead)
            {
                var clientHmacKey = ComputeEncryptionKey(kexAlg, exchangeHash, clientHmac.KeySize >> 3, sharedSecret, 'E');
                clientHmacAlg = clientHmac.Hmac(clientHmacKey);
            }
            if (!serverEncryption.IsAead)
            {
                var serverHmacKey = ComputeEncryptionKey(kexAlg, exchangeHash, serverHmac.KeySize >> 3, sharedSecret, 'F');
                serverHmacAlg = serverHmac.Hmac(serverHmacKey);
            }

            var algorithms = new Algorithms
            {
                KeyExchange = kexAlg,
                PublicKey = hostKeyAlg,
                ClientEncryption = clientEncryption,
                ServerEncryption = serverEncryption,
                ClientHmac = clientHmacAlg,
                ServerHmac = serverHmacAlg,
                ClientCompression = _compressionAlgorithms[_exchangeContext.ClientCompression](),
                ServerCompression = _compressionAlgorithms[_exchangeContext.ServerCompression](),
                ClientHmacIsEtm = clientHmac.IsEtm,
                ServerHmacIsEtm = serverHmac.IsEtm,
            };

            return algorithms;
        }

        private byte[] ComputeEncryptionKey(KexAlgorithm kexAlg, byte[] exchangeHash, int blockSize, byte[] sharedSecret, char letter)
        {
            var keyBuffer = new byte[blockSize];
            var keyBufferIndex = 0;
            var currentHashLength = 0;
            byte[] currentHash = null;

            while (keyBufferIndex < blockSize)
            {
                var writer = new SshDataWriter()
                    .WriteMpint(sharedSecret)
                    .WriteBytes(exchangeHash);

                if (currentHash == null)
                {
                    writer.Write((byte)letter);
                    writer.WriteBytes(SessionId);
                }
                else
                {
                    writer.WriteBytes(currentHash);
                }

                currentHash = kexAlg.ComputeHash(writer.ToByteArray());

                currentHashLength = Math.Min(currentHash.Length, blockSize - keyBufferIndex);
                Array.Copy(currentHash, 0, keyBuffer, keyBufferIndex, currentHashLength);

                keyBufferIndex += currentHashLength;
            }

            return keyBuffer;
        }

        /// <summary>
        /// Compute the SSH packet MAC <c>seq ‖ a ‖ b</c> straight into
        /// <paramref name="destination"/> via the Span-based HMAC core
        /// (HmacAlgorithm.ComputeHash overload). Caller owns the destination
        /// — typically a stackalloc Span sized to DigestLength, so the
        /// per-packet MAC computation is now zero-allocation.
        /// </summary>
        private void ComputeHmac(HmacAlgorithm alg, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, uint seq, Span<byte> destination)
        {
            alg.ComputeHash(a, b, seq, destination);
        }

        internal SshService RegisterService(string serviceName, UserAuthArgs auth = null)
        {
            ArgumentNullException.ThrowIfNull(serviceName);

            SshService service = null;
            switch (serviceName)
            {
                case "ssh-userauth":
                    if (GetService<UserAuthService>() == null)
                        service = new UserAuthService(this);
                    break;
                case "ssh-connection":
                    if (auth != null && GetService<ConnectionService>() == null)
                        service = new ConnectionService(this, auth);
                    break;
            }
            if (service != null)
            {
                if (ServiceRegistered != null)
                    ServiceRegistered(this, service);

                _services.Add(service);
            }
            return service;
        }

        private class Algorithms
        {
            public KexAlgorithm KeyExchange;
            public PublicKeyAlgorithm PublicKey;
            public EncryptionAlgorithm ClientEncryption;
            public EncryptionAlgorithm ServerEncryption;
            public HmacAlgorithm ClientHmac;
            public HmacAlgorithm ServerHmac;
            public CompressionAlgorithm ClientCompression;
            public CompressionAlgorithm ServerCompression;
            public bool ClientHmacIsEtm;
            public bool ServerHmacIsEtm;
        }

        private class ExchangeContext
        {
            public string KeyExchange;
            public string PublicKey;
            public string ClientEncryption;
            public string ServerEncryption;
            public string ClientHmac;
            public string ServerHmac;
            public string ClientCompression;
            public string ServerCompression;

            public byte[] ClientKexInitPayload;
            public byte[] ServerKexInitPayload;

            public Algorithms NewAlgorithms;
        }
    }
}
