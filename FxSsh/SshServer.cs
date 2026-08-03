using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Logging;

namespace FxSsh
{
    public class SshServer : IDisposable
    {
        private readonly object _lock = new();
        private readonly List<Session> _sessions = [];
        private readonly Dictionary<string, string> _hostKey = [];
        private bool _isDisposed;
        private bool _started;
        private TcpListener _listenser = null;

        public SshServer()
            : this(new StartingInfo())
        { }

        public SshServer(StartingInfo info)
        {
            ArgumentNullException.ThrowIfNull(info);

            StartingInfo = info;
        }

        public StartingInfo StartingInfo { get; private set; }

        public event EventHandler<Session> ConnectionAccepted;
        public event EventHandler<Exception> ExceptionRaised;

        public void Start()
        {
            lock (_lock)
            {
                CheckDisposed();
                if (_started)
                    throw new InvalidOperationException("The server is already started.");

                _listenser = StartingInfo.LocalAddress == IPAddress.IPv6Any
                    ? TcpListener.Create(StartingInfo.Port) // dual stack
                    : new TcpListener(StartingInfo.LocalAddress, StartingInfo.Port);
                _listenser.ExclusiveAddressUse = false;
                _listenser.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                _listenser.Start();
                BeginAcceptSocket();

                _started = true;

                Log.Info($"SSH server listening on {StartingInfo.LocalAddress}:{StartingInfo.Port}.");
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                CheckDisposed();
                if (!_started)
                    throw new InvalidOperationException("The server is not started.");

                _listenser.Stop();

                _isDisposed = true;
                _started = false;

                Log.Info("SSH server stopped.");

                foreach (var session in _sessions.ToArray())
                {
                    try
                    {
                        session.Disconnect();
                    }
                    catch
                    {
                    }
                }
            }
        }

        public void AddHostKey(string type, string xml)
        {
            ArgumentNullException.ThrowIfNull(type);
            ArgumentNullException.ThrowIfNull(xml);

            if (!_hostKey.ContainsKey(type))
                _hostKey.Add(type, xml);
        }

        private void BeginAcceptSocket()
        {
            try
            {
                _listenser.BeginAcceptSocket(AcceptSocket, null);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (Exception ex)
            {
                Log.Fail("Listener accept failed.", ex);
                if (_started)
                    BeginAcceptSocket();
            }
        }

        private void AcceptSocket(IAsyncResult ar)
        {
            try
            {
                var socket = _listenser.EndAcceptSocket(ar);
                Task.Factory.StartNew(() =>
                {
                    var remote = socket.RemoteEndPoint?.ToString() ?? "?";
                    var session = new Session(socket, _hostKey, StartingInfo.ServerBanner);
                    session.Disconnected += (ss, ee) =>
                    {
                        lock (_lock) _sessions.Remove(session);
                    };
                    lock (_lock)
                        _sessions.Add(session);
                    try
                    {
                        Log.Info($"Session accepted from {remote}.");
                        ConnectionAccepted?.Invoke(this, session);
                        Log.Debug($"Session {remote} establishing protocol...");
                        session.EstablishConnection();
                    }
                    catch (SshConnectionException ex)
                    {
                        if (ex.DisconnectReason == DisconnectReason.ConnectionLost)
                        {
                            // Peer closed/reset the TCP connection (e.g. normal
                            // exit after our channel teardown) - not an error.
                            Log.Debug($"Session {remote} connection closed: {ex.Message}");
                        }
                        else
                        {
                            Log.Warn($"Session {remote} aborted: {ex.Message}");
                        }
                        session.Disconnect(ex.DisconnectReason, ex.Message);
                        ExceptionRaised?.Invoke(this, ex);
                    }
                    catch (Exception ex)
                    {
                        Log.Fail($"Session {remote} failed.", ex);
                        session.Disconnect();
                        ExceptionRaised?.Invoke(this, ex);
                    }
                }, TaskCreationOptions.LongRunning);
            }
            catch (Exception ex)
            {
                Log.Fail("Accept callback failed.", ex);
            }
            finally
            {
                BeginAcceptSocket();
            }
        }

        private void CheckDisposed()
        {
            if (_isDisposed)
                throw new ObjectDisposedException(GetType().FullName);
        }

        #region IDisposable
        public void Dispose()
        {
            lock (_lock)
            {
                if (_isDisposed)
                    return;
                Stop();
            }
        }
        #endregion
    }
}
