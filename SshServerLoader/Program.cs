using FxSsh;
using FxSsh.Services;
using MiniTerm;
using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SshServerLoader
{
    class Program
    {
        static int windowWidth, windowHeight;

        static void Main(string[] args)
        {
            var rsa2048BitPem = @"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQClBPKsmiTxCoez
E4Wt4nvNDVjLtkGQPUS/SbhJCL8J7pKrvsKRyXKM9GjGdxA7GKZR7sjqCWCU12oD
+EJuf/mpcA0JsBY4gUU8bp95U5mEM+ZOr2aNXYXAXy/J6GQRyd1jgkD2pm1qsWZJ
ahvXNJGMgx1lqI9woKU+PRssMtv1YupAxsSlo+xcfvC57fkaKIwUeCr6CkUlpIJN
zP5lvatKcpmjiWLSRHUpypx2wgZPz4SnB2qE77UH/yu1DlcsQgbVa7nr+qMWfxP7
Cpa+eTJC19c1GP+XxFaeqXDtuGaRlfBX/iihEcBnQuvsZJLg5jN0WKqvnpDfHgh/
M4IopC2pAgMBAAECggEBAImt6ibV6NJvHa7sL9FXMEFxzE8SffsxEyWiBS5yLKnF
sfu3CbEG6RrvZGeJuTIFK+caGekh78HfRGWRgSOehJe4lDgsAS4dtL1p8oYQmPnz
L0khEKgLimdpQ37q9GrfCGZYq4jebFXjMts3u4i/JFyenC1QCHVIovWdmAk1Wc2N
5bY+qlQZ4dSBl15cqNg0w4bbEF+yT+fOMm/raZANTr/IDIt88LcKpyimvUSGlZEE
OWx4hXAPbF4h/tqeH4O+Xzmtq/1pWwdbwNqWwOXow320c97U4ofCuDXcy0TeOwiX
gcPnaG99jX4Cy+IwdcVnDsJpN4FC2/sm1kGeOTRpIl0CgYEAy8gPV5RESpOyQ00j
dr36JQoymLwXDS114tuMPF7dX5YX3S+yyhl0ADa11tVH15CzOaVSF1wfxDeb1TRs
XcJoZBsxlH24BMPETB1ADy43pslRrkex54hcM4jDe3OYBTsVmV5A2sdxFGEKAbPn
uWsk8jeZ9AsEV3M2vinzJmS5XVsCgYEAz04dSW0GXiTBESYmno9DJiyx3dT4T0eq
bwtpZPCShEjU4BChwFg9V5fAmzw1iCrdYD68mwcxQYurp3Vgqo6u1YogRpeNfljq
VpKnVDbd3a1CTYYyWw81f4HzflpmWLgq1BGKkdwD83xZaFh7Y46cm+xEtrJpiVFM
GTagAokFvEsCgYB1EouV4g1V1wJ73c45Aq26J+CnlK+dl3d5jG5FpK6DosQ1A5kw
uGzHTqcrND7g3jXJMWw3FWr+nH//fe2f8/drQ6A5UfytaBbXL5rE3eWFAXXWrUPM
468swC6mNuOoZahkAx05U4lojtNj5QqEoMSKD114MfgdkYhquckCTq2brwKBgQC5
s1zS0II6xSvZw9YmhWj+gl0WvVduFWGcNZnE3SgyrddbnCp5VdIlbAASTx4ZC2Th
eXGUYh4CfC5ZRPFB96ywBxqggdQzEU1iHd8ctkWK9VCGh6cGIRqoTO2lCy/RW7Cp
5ci+nls/uu2QZmqppS+vETgAfNPDOXs0vtUZUEs9/wKBgDNQonVvTTQIRbaRbxXu
eVqxAVYBb8PSPBjfigb4/sGzu4iYaxuCHOkA8AK9B9SmGjaQHJ4h9t+kJKe9xNie
v7sG5pguzUyd+AJIafbeh2Iryva/Nw3Shb7Jl6EX/lX3o/B9hRziWKV0IvwCUF/1
iyxhUEyZT7ugi8eNl5zVJgmN
-----END PRIVATE KEY-----";

            var server = new SshServer();
            server.AddHostKey("rsa-sha2-256", rsa2048BitPem);
            server.AddHostKey("rsa-sha2-512", rsa2048BitPem);
            server.ConnectionAccepted += server_ConnectionAccepted;

            server.Start();

            Task.Delay(-1).Wait();
        }

        static void server_ConnectionAccepted(object sender, Session e)
        {
            Console.WriteLine("Accepted a client.");

            e.ServiceRegistered += e_ServiceRegistered;
            e.KeysExchanged += e_KeysExchanged;
        }

        private static void e_KeysExchanged(object sender, KeyExchangeArgs e)
        {
            foreach (var keyExchangeAlg in e.KeyExchangeAlgorithms)
            {
                Console.WriteLine("Key exchange algorithm: {0}", keyExchangeAlg);
            }
        }

        static void e_ServiceRegistered(object sender, SshService e)
        {
            var session = (Session)sender;
            Console.WriteLine("Session {0} requesting {1}.",
                BitConverter.ToString(session.SessionId).Replace("-", ""), e.GetType().Name);

            if (e is UserauthService)
            {
                var service = (UserauthService)e;
                service.Userauth += service_Userauth;
            }
            else if (e is ConnectionService)
            {
                var service = (ConnectionService)e;
                service.CommandOpened += service_CommandOpened;
                service.EnvReceived += service_EnvReceived;
                service.PtyReceived += service_PtyReceived;
                service.TcpForwardRequest += service_TcpForwardRequest;
                service.WindowChange += Service_WindowChange;
            }
        }

        static void Service_WindowChange(object sender, WindowChangeArgs e)
        {
            // DEMO MiniTerm not support change window size
        }

        static void service_TcpForwardRequest(object sender, TcpRequestArgs e)
        {
            Console.WriteLine("Received a request to forward data to {0}:{1}", e.Host, e.Port);

            var allow = true;  // func(e.Host, e.Port, e.AttachedUserauthArgs);

            if (!allow)
                return;

            var tcp = new TcpForwardService(e.Host, e.Port, e.OriginatorIP, e.OriginatorPort);
            e.Channel.DataReceived += (ss, ee) => tcp.OnData(ee);
            e.Channel.CloseReceived += (ss, ee) => tcp.OnClose();
            tcp.DataReceived += (ss, ee) => e.Channel.SendData(ee);
            tcp.CloseReceived += (ss, ee) => e.Channel.SendClose();
            tcp.Start();
        }

        static void service_PtyReceived(object sender, PtyArgs e)
        {
            Console.WriteLine("Request to create a PTY received for terminal type {0}", e.Terminal);
            windowWidth = (int)e.WidthChars;
            windowHeight = (int)e.HeightRows;
        }

        static void service_EnvReceived(object sender, EnvironmentArgs e)
        {
            Console.WriteLine("Received environment variable {0}:{1}", e.Name, e.Value);
        }

        static void service_Userauth(object sender, UserauthArgs e)
        {
            Console.WriteLine("Client {0} fingerprint: {1}.", e.KeyAlgorithm, e.Fingerprint);

            e.Result = true;
        }

        static void service_CommandOpened(object sender, CommandRequestedArgs e)
        {
            Console.WriteLine($"Channel {e.Channel.ServerChannelId} runs {e.ShellType}: \"{e.CommandText}\".");

            var allow = true;  // func(e.ShellType, e.CommandText, e.AttachedUserauthArgs);

            if (!allow)
                return;

            if (e.ShellType == "shell")
            {
                // requirements: Windows 10 RedStone 5, 1809
                // also, you can call powershell.exe
                var terminal = new Terminal("cmd.exe", windowWidth, windowHeight);

                e.Channel.DataReceived += (ss, ee) => terminal.OnInput(ee);
                e.Channel.CloseReceived += (ss, ee) => terminal.OnClose();
                terminal.DataReceived += (ss, ee) => e.Channel.SendData(ee);
                terminal.CloseReceived += (ss, ee) => e.Channel.SendClose(ee);

                terminal.Run();
            }
            else if (e.ShellType == "exec")
            {
                var parser = new Regex(@"(?<cmd>git-receive-pack|git-upload-pack|git-upload-archive) \'/?(?<proj>.+)\.git\'");
                var match = parser.Match(e.CommandText);
                var command = match.Groups["cmd"].Value;
                var project = match.Groups["proj"].Value;

                var git = new GitService(command, project);

                e.Channel.DataReceived += (ss, ee) => git.OnData(ee);
                e.Channel.CloseReceived += (ss, ee) => git.OnClose();
                git.DataReceived += (ss, ee) => e.Channel.SendData(ee);
                git.CloseReceived += (ss, ee) => e.Channel.SendClose(ee);

                git.Start();
            }
            else if (e.ShellType == "subsystem")
            {
                // do something more
            }
        }
    }
}
