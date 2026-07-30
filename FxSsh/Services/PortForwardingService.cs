using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace FxSsh.Services
{
    /// <summary>
    /// Server-side reverse port forwarding (RFC 4254 section 7.2).
    ///
    /// Bound to a single (address, port) endpoint requested by the peer via
    /// SSH_MSG_GLOBAL_REQUEST "tcpip-forward". Each inbound TCP connection is
    /// reported back to the peer via SSH_MSG_CHANNEL_OPEN "forwarded-tcpip"
    /// through the supplied channel-open factory; the peer then speaks SSH
    /// channel data into the forwarded socket. Closing the service (via
    /// "cancel-tcpip-forward" or session teardown) stops the listener and
    /// tears down any in-flight forwarded channels.
    /// </summary>
    public sealed class PortForwardingService : IDisposable
    {
        private readonly IPEndPoint _endpoint;
        private readonly Func<string, uint, string, uint, Channel> _openForwardedChannel;
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly List<(Channel channel, Socket socket)> _bridges = [];
        private readonly object _bridgeLocker = new();

        /// <summary>Bound host the listener actually used (may differ from requested when host was empty).</summary>
        public string BoundAddress { get; }

        /// <summary>Bound port the listener actually used ( RFC 4254: when requested port is 0, return the OS-assigned port).</summary>
        public uint BoundPort { get; private set; }

        /// <summary>Raised (best-effort) when a forwarded channel is torn down because the peer closed it or the listener stopped.</summary>
        public event EventHandler<Channel> ForwardedChannelClosed;

        /// <summary>
        /// </summary>
        /// <param name="address">Bind address as requested by the peer. Empty/null selects IPv4Any.</param>
        /// <param name="port">Bind port. 0 lets the OS choose; the chosen port is exposed via BoundPort.</param>
        /// <param name="openForwardedChannel">Factory that opens an outbound forwarded-tcpip channel
        /// and returns the Channel handle. Receives (boundAddress, boundPort, originatorIP, originatorPort).</param>
        public PortForwardingService(string address, uint port,
            Func<string, uint, string, uint, Channel> openForwardedChannel)
        {
            if (port > ushort.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(port));

            _openForwardedChannel = openForwardedChannel
                ?? throw new ArgumentNullException(nameof(openForwardedChannel));

            var ip = string.IsNullOrEmpty(address) ? IPAddress.Any : IPAddress.Parse(address);
            _endpoint = new IPEndPoint(ip, (int)port);
            BoundAddress = ip.ToString();
            // BoundPort is set after Start() resolves the OS-assigned port.

            _listener = new TcpListener(_endpoint);
        }

        public void Start()
        {
            _listener.Start();
            BoundPort = (uint)((IPEndPoint)_listener.LocalEndpoint).Port;
            Task.Run(AcceptLoop);
        }

        private void AcceptLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                Socket client;
                try
                {
                    client = _listener.AcceptSocket();
                }
                catch (SocketException) { break; }   // listener stopped
                catch (ObjectDisposedException) { break; }

                var remote = (IPEndPoint)client.RemoteEndPoint;

                // Open an outbound forwarded-tcpip channel to the peer. The
                // factory is responsible for sending SSH_MSG_CHANNEL_OPEN and
                // returning the Channel handle. If the peer rejects, drop the
                // TCP connection silently.
                Channel channel;
                try
                {
                    channel = _openForwardedChannel(BoundAddress, BoundPort,
                        remote.Address.ToString(), (uint)remote.Port);
                }
                catch
                {
                    try { client.Close(); } catch { }
                    continue;
                }

                if (channel == null)
                {
                    try { client.Close(); } catch { }
                    continue;
                }

                Bridge(channel, client);
            }
        }

        /// <summary>Wire a forwarded channel to a socket: socket→channel data, channel close→socket close.</summary>
        private void Bridge(Channel channel, Socket socket)
        {
            lock (_bridgeLocker)
                _bridges.Add((channel, socket));

            channel.DataReceived += (_, data) =>
            {
                try { if (socket.Connected) socket.Send(data); } catch { }
            };
            channel.CloseReceived += (_, _) =>
            {
                try { if (socket.Connected) socket.Shutdown(SocketShutdown.Send); } catch { }
            };

            // Socket → channel pump.
            Task.Run(() =>
            {
                var buf = new byte[1024 * 32];
                try
                {
                    while (socket.Connected && !_cts.IsCancellationRequested)
                    {
                        int n;
                        try { n = socket.Receive(buf); }
                        catch (SocketException) { break; }
                        catch (ObjectDisposedException) { break; }

                        if (n <= 0) break;
                        channel.SendData(n == buf.Length ? buf : buf[..n]);
                    }
                }
                catch { }
                finally
                {
                    channel.SendEof();
                    try { socket.Close(); } catch { }

                    lock (_bridgeLocker)
                        _bridges.Remove((channel, socket));

                    ForwardedChannelClosed?.Invoke(this, channel);
                }
            });
        }

        public void Dispose()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }

            lock (_bridgeLocker)
            {
                foreach (var (channel, socket) in _bridges.ToArray())
                {
                    try { socket.Close(); } catch { }
                    // channel is torn down by the peer or CloseService; do not ForceClose here.
                }
                _bridges.Clear();
            }

            _cts.Dispose();
        }
    }
}
