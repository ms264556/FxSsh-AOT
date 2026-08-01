using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SshServerLoader
{
    public class TcpForwardService
    {
        private Socket _socket;
        private string _host;
        private int _port;
        private readonly BlockingCollection<byte[]> _sendQueue = [];
        private readonly CancellationTokenSource _cts = new();
        private bool _closed;

        public TcpForwardService(string host, int port, string originatorIP, int originatorPort)
        {
            _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            _host = host;
            _port = port;
        }

        public event EventHandler<byte[]> DataReceived;
        public event EventHandler CloseReceived;

        public void Start()
        {
            Task.Run(() =>
            {
                try
                {
                    MessageLoop();
                }
                catch
                {
                    OnClose();
                }
            });
        }

        /// <summary>
        /// Called on the SSH ConnectionService.MessageLoop thread. Must never
        /// block that thread: the SSH receive loop and window adjustments share
        /// it, so a blocking socket send here would stall the peer's upload
        /// (its send window is replenished by the same thread). Instead the
        /// data is queued and flushed by a dedicated send thread.
        /// </summary>
        public void OnData(byte[] data)
        {
            try
            {
                _sendQueue.Add(data);
            }
            catch
            {
                OnClose();
            }
        }

        public void OnClose()
        {
            try
            {
                _socket.Shutdown(SocketShutdown.Send);
            }
            catch { }
        }

        private void MessageLoop()
        {
            _socket.Connect(_host, _port);

            // Dedicated send thread: serializes socket.Send so the SSH
            // MessageLoop thread never blocks on the local TCP peer.
            Task.Run(SendLoop);

            var bytes = new byte[1024 * 64];
            while (true)
            {
                var len = _socket.Receive(bytes);
                if (len <= 0)
                    break;

                var data = bytes.Length != len
                    ? bytes.Take(len).ToArray()
                    : bytes;
                DataReceived?.Invoke(this, data);
            }
            CloseReceived?.Invoke(this, EventArgs.Empty);
            Finish();
        }

        private void SendLoop()
        {
            try
            {
                foreach (var data in _sendQueue.GetConsumingEnumerable(_cts.Token))
                {
                    if (data.Length == 0)
                        continue;
                    _socket.Send(data);
                }
            }
            catch
            {
                // Socket closed or canceled; nothing to do.
            }
        }

        private void Finish()
        {
            if (_closed)
                return;
            _closed = true;

            _cts.Cancel();
            try { _socket.Close(); } catch { }
        }
    }
}
