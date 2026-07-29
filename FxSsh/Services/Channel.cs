using FxSsh.Messages.Connection;
using System;
using System.Threading;

namespace FxSsh.Services
{
    public abstract class Channel
    {
        protected ConnectionService _connectionService;
        protected EventWaitHandle _sendingWindowWaitHandle = new ManualResetEvent(false);
        private readonly object _windowLocker = new object();
        private bool _forceClosed;

        public Channel(ConnectionService connectionService,
            uint clientChannelId, uint clientInitialWindowSize, uint clientMaxPacketSize,
            uint serverChannelId)
        {
            ArgumentNullException.ThrowIfNull(connectionService);

            _connectionService = connectionService;

            ClientChannelId = clientChannelId;
            ClientInitialWindowSize = clientInitialWindowSize;
            ClientWindowSize = clientInitialWindowSize;
            ClientMaxPacketSize = clientMaxPacketSize;

            ServerChannelId = serverChannelId;
            ServerInitialWindowSize = Session.InitialLocalWindowSize;
            ServerWindowSize = Session.InitialLocalWindowSize;
            ServerMaxPacketSize = Session.LocalChannelDataPacketSize;
        }

        public uint ClientChannelId { get; private set; }
        public uint ClientInitialWindowSize { get; private set; }
        public uint ClientWindowSize { get; protected set; }
        public uint ClientMaxPacketSize { get; private set; }

        public uint ServerChannelId { get; private set; }
        public uint ServerInitialWindowSize { get; private set; }
        public uint ServerWindowSize { get; protected set; }
        public uint ServerMaxPacketSize { get; private set; }

        public bool ClientClosed { get; private set; }
        public bool ClientMarkedEof { get; private set; }
        public bool ServerClosed { get; private set; }
        public bool ServerMarkedEof { get; private set; }

        public event EventHandler<byte[]> DataReceived;
        public event EventHandler EofReceived;
        public event EventHandler CloseReceived;
        public event EventHandler<WindowChangeArgs> WindowChange;

        public void SendData(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            if (data.Length == 0)
            {
                return;
            }

            var msg = new ChannelDataMessage();
            msg.RecipientChannel = ClientChannelId;

            var total = (uint)data.Length;
            var offset = 0L;
            byte[] buf = null;
            do
            {
                uint packetSize;
                lock (_windowLocker)
                {
                    packetSize = Math.Min(Math.Min(ClientWindowSize, ClientMaxPacketSize), total);
                    if (packetSize > 0)
                        ClientWindowSize -= packetSize;
                }

                if (packetSize == 0)
                {
                    _sendingWindowWaitHandle.WaitOne();
                    continue;
                }

                if (buf == null || packetSize != buf.Length)
                    buf = new byte[packetSize];
                Array.Copy(data, offset, buf, 0, packetSize);

                msg.Data = buf;
                _connectionService._session.SendMessage(msg);

                total -= packetSize;
                offset += packetSize;
            } while (total > 0);
        }

        public void SendEof()
        {
            if (ServerMarkedEof)
                return;

            ServerMarkedEof = true;
            var msg = new ChannelEofMessage { RecipientChannel = ClientChannelId };
            _connectionService._session.SendMessage(msg);
        }

        public void SendClose(uint? exitCode = null)
        {
            if (ServerClosed)
                return;

            ServerClosed = true;
            if (exitCode.HasValue)
                _connectionService._session.SendMessage(new ExitStatusMessage { RecipientChannel = ClientChannelId, ExitStatus = exitCode.Value });
            _connectionService._session.SendMessage(new ChannelCloseMessage { RecipientChannel = ClientChannelId });

            CheckBothClosed();
        }

        /// <summary>
        /// Close the channel after the process was terminated by a signal,
        /// emitting an "exit-signal" channel request (RFC 4254 section 10.2) before
        /// SSH_MSG_CHANNEL_CLOSE. Mutually exclusive with SendClose(exitCode):
        /// a channel reports EITHER exit-status OR exit-signal, never both.
        /// </summary>
        /// <param name="signalName">Signal name WITHOUT "SIG" prefix (e.g. "TERM", "KILL", "SEGV").</param>
        /// <param name="coreDumped">Whether the process produced a core dump.</param>
        /// <param name="errorMessage">Human-readable explanation (may be empty).</param>
        /// <param name="language">Language tag per RFC 3066 (defaults to "en").</param>
        public void SendSignalClose(string signalName, bool coreDumped = false, string errorMessage = "", string language = "en")
        {
            if (ServerClosed)
                return;

            ServerClosed = true;
            _connectionService._session.SendMessage(new ExitSignalMessage
            {
                RecipientChannel = ClientChannelId,
                SignalName = signalName ?? string.Empty,
                CoreDumped = coreDumped,
                ErrorMessage = errorMessage ?? string.Empty,
                Language = language ?? "en",
            });
            _connectionService._session.SendMessage(new ChannelCloseMessage { RecipientChannel = ClientChannelId });

            CheckBothClosed();
        }

        internal void OnData(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            ServerAttemptAdjustWindow((uint)data.Length);

            DataReceived?.Invoke(this, data);
        }

        internal void OnEof()
        {
            ClientMarkedEof = true;

            EofReceived?.Invoke(this, EventArgs.Empty);
        }

        internal void OnClose()
        {
            ClientClosed = true;

            CloseReceived?.Invoke(this, EventArgs.Empty);

            CheckBothClosed();
        }

        internal void OnWindowChange(WindowChangeArgs args)
        {
            WindowChange?.Invoke(this, args);
        }

        internal void ClientAdjustWindow(uint bytesToAdd)
        {
            lock (_windowLocker)
                ClientWindowSize += bytesToAdd;

            // pulse multithreadings in same time and unsignal until thread switched
            // don't try to use AutoResetEvent
            _sendingWindowWaitHandle.Set();
            Thread.Sleep(1);
            _sendingWindowWaitHandle.Reset();
        }

        private void ServerAttemptAdjustWindow(uint messageLength)
        {
            ServerWindowSize -= messageLength;
            if (ServerWindowSize <= ServerMaxPacketSize)
            {
                _connectionService._session.SendMessage(new ChannelWindowAdjustMessage
                {
                    RecipientChannel = ClientChannelId,
                    BytesToAdd = ServerInitialWindowSize - ServerWindowSize
                });
                ServerWindowSize = ServerInitialWindowSize;
            }
        }

        private void CheckBothClosed()
        {
            if (ClientClosed && ServerClosed)
            {
                ForceClose();
            }
        }

        internal void ForceClose()
        {
            // ForceClose can be reached more than once: SendClose() drives it
            // when the server side closes first, and OnClose() drives it again
            // when the client's CHANNEL_CLOSE arrives (or vice versa), plus
            // any external listener wired onto CloseReceived can re-enter it.
            // The wait handle below is a single-use resource; Close() then Set()
            // on a second pass throws ObjectDisposedException. Guard with a
            // flag so teardown happens exactly once.
            if (_forceClosed)
                return;
            _forceClosed = true;

            _connectionService.RemoveChannel(this);
            _sendingWindowWaitHandle.Set();
            _sendingWindowWaitHandle.Close();
        }
    }
}
