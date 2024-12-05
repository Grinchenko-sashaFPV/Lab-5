using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace FirewallManager
{
    internal class IpScanner
    {
        public static void ScanIpRange(string range, string portRange)
        {
            Console.WriteLine($"Scanning range: {range}, Ports: {portRange}");
            var rangeParts = range.Split('-');
            var startIp = IPAddress.Parse(rangeParts[0]);
            var endIp = IPAddress.Parse(rangeParts[1]);

            var ports = ParsePortRange(portRange);

            for (var ip = startIp; CompareIp(ip, endIp) <= 0; ip = IncrementIp(ip))
            {
                Console.WriteLine($"Scanning IP: {ip}");
                Parallel.ForEach(ports, port =>
                {
                    if (IsPortOpen(ip.ToString(), port, TimeSpan.FromSeconds(1)))
                    {
                        Console.WriteLine($"Open port {port} on {ip}");
                        var serviceName = GetServiceName(port);
                        if (!string.IsNullOrEmpty(serviceName))
                        {
                            Console.WriteLine($"Service on port {port}: {serviceName}");
                        }
                    }
                });
            }
        }

        private static string GetServiceName(int port)
        {
            try
            {
                // Here we simulate fetching the service name; extend for real cases
                return port switch
                {
                    80 => "HTTP",
                    443 => "HTTPS",
                    21 => "FTP",
                    22 => "SSH",
                    25 => "SMTP",
                    _ => "Unknown"
                };
            }
            catch
            {
                return "Unknown";
            }
        }

        private static bool IsPortOpen(string host, int port, TimeSpan timeout)
        {
            try
            {
                using var client = new TcpClient();
                var result = client.BeginConnect(host, port, null, null);
                var success = result.AsyncWaitHandle.WaitOne(timeout);
                if (success)
                {
                    client.EndConnect(result);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        private static IPAddress IncrementIp(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            for (var i = bytes.Length - 1; i >= 0; i--)
            {
                if (++bytes[i] != 0)
                    break;
            }
            return new IPAddress(bytes);
        }

        private static int CompareIp(IPAddress ip1, IPAddress ip2)
        {
            var bytes1 = ip1.GetAddressBytes();
            var bytes2 = ip2.GetAddressBytes();
            for (var i = 0; i < bytes1.Length; i++)
            {
                var diff = bytes1[i] - bytes2[i];
                if (diff != 0) return diff;
            }
            return 0;
        }

        private static int[] ParsePortRange(string range)
        {
            var parts = range.Split('-');
            var start = int.Parse(parts[0]);
            var end = int.Parse(parts[1]);
            var ports = new int[end - start + 1];
            for (int i = 0; i < ports.Length; i++)
            {
                ports[i] = start + i;
            }
            return ports;
        }
    }
}
