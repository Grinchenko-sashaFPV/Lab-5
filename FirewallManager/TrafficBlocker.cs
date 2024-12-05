using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FirewallManager
{
    internal class TrafficBlocker
    {
        private const string _command = "advfirewall firewall add rule";

        public static void BlockTrafficFromIp(string ip)
        {
            ExecuteNetshCommand($"{_command} name=\"Block {ip}\" dir=in action=block remoteip={ip}");
            Console.WriteLine($"Traffic from {ip} is now blocked.");
        }

        public static void RestrictPorts(string ports)
        {
            ExecuteNetshCommand($"{_command} name=\"Restrict Ports {ports}\" dir=in action=block protocol=TCP localport={ports}");
            Console.WriteLine($"Traffic to ports {ports} is now restricted.");
        }

        public static void AllowTrustedSources(string ipRange)
        {
            ExecuteNetshCommand($"{_command} name=\"Allow {ipRange}\" dir=in action=allow remoteip={ipRange}");
            Console.WriteLine($"Traffic from {ipRange} is now allowed.");
        }

        private static void ExecuteNetshCommand(string command)
        {
            try
            {
                ProcessStartInfo psi = new()
                {
                    FileName = "netsh",
                    Arguments = command,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = false
                };

                using var process = Process.Start(psi);
                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();

                process.WaitForExit();

                if (!string.IsNullOrEmpty(output))
                {
                    Console.WriteLine($"Output: {output}");
                }

                if (!string.IsNullOrEmpty(error))
                {
                    Console.WriteLine($"Error: {error}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to execute command: {ex.Message}");
            }
        }
    }
}
