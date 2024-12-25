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
            var rsa2048BitKey = "BwIAAACkAABSU0EyAAgAAAEAAQCpLaQogjN/CB7fkJ6vqlh0M+bgkmTs60JnwBGhKP5X8JWRZrjtcKmeVsSX/xg119dCMnm+lgr7E38Wo/rruWvVBkIsVw61K/8Hte+EagenhM9PBsJ2nMopdUTSYomjmXJKq71l/sxNgqQlRQr6KngUjCga+e258H5c7KOlxMZA6mL12zIsGz0+paBwj6hlHYOMkTTXG2pJZrFqbab2QIJj3ckRZOjJL1/AhV2NZq9O5jOEmVN5n248RYE4FrAJDXCp+X9uQvgDateUYAnqyO5Rphg7EHfGaPSMcsmRwr6rku4JvwhJuEm/RD2QQbbLWA3Ne+KthROzhwrxJJqs8gSlW125ZCbzKb42c1cEC/SZN/Ika7nnswEKYRRxx9pAXpkVOwWYc3vDiDNciOexR65RyaY3Lg9AHUzEwwS4fZQxG2Rowl1sNNWbN8QfXBdSpTmzkNdH1da1NgB0GcqyL90Xll/dXjyM2+J1LQ0XvJgyCiX6vXYjTUOyk0pElFcPyMtLvAWJAqA2GUxRiWmytkTsm5yOY3tYaFl88wPckYoR1Cq4WGZafvOBfzUPWzKGTUKt3d02VKeSVupYfo2XRiCK1a6OqmB1p6uLQTEHm7w+YN0qiDU8m8CXVz1YwKEQ4NRIhJLwZGkLb6pHT/jU3bEsJkOPniYmEcEkXgZtSR1Oz6+brU4CyblqiJEd+DF4XQ+KxKCECuVj045oiVM5HQNkqGWo4zamLsAsr+PMQ63WdQGF5d3Emi/XFmit/FE5oENr9/Of7X3/f5z+ahU3bDHJNd7gPjQrp07HbLgwmQM1xKKDrqRFbox5d5edr5Sn4Ce6rQI5zt17AtdVDeKVixJ1/z1LUBnVvjR7OcPTfAA4Ea8vpalqZpDtuj9bnr7I5amwW9EvC6XtTKgaIQanh4ZQ9YpFthzfHWJNETPUgaAaB7Cs90HxRFkufAIeYpRxeeFkCxkeTxIAbCXSVXkqnFvXrTIo3cSZNZxhFW5XvRZdgv5ohSbWw9krxTqC0NJcs7mNCSbVnJeNx4ugu0+ZTFBhLIv1X1AC/CJ0pVjiHIV98KP3Vf4XoZfJvoXSDTe/9sorYofe9mlIAvidTM0umOYGu7+e2MS9pySk3/YhnhyQNhqm1Ae9AvAA6RyCG2uYiLuzwf74BorfGDzSw28BVgGxWnnuFW+RtkUINE1vdaJQM10iaTQ5nkHWJvvbQoE3acIOZ8V1MOLLAn6NfW9o58OBlwg73kTL3DW4wofi1N5ztH3D6OXAltrAWwdbaf2rrTlfvoMfntr+IV5sD3CFeGw5BJGVhkS9piinCrfwfIsMyL9ODZBp628yzudPsl8Q24bDNNioXF6XgdThGVSqPrbljc1ZNQmYnfWiSHUIUC2cnlwkv4i7N9sy41Vs3oirWGYI32r06n5DaWeKC6gQIUkv8/mYEIbyab20HS4BLDiUuJeEniOBkWVE38HvIekZGucrBTK5iWdk7xrpBrEJt/uxxaksci4FoiUTMft9Ek/McUEwV9Ev7K4db9Lo1SbqrYk=";

            var server = new SshServer();
            server.AddHostKey("rsa-sha2-256", rsa2048BitKey);
            server.AddHostKey("rsa-sha2-512", rsa2048BitKey);
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
