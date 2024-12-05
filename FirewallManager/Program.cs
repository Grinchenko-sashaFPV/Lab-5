using FirewallManager;

Console.WriteLine("Firewall Management Tool");
Console.WriteLine("1. Block traffic from specific IP");
Console.WriteLine("2. Restrict access to specific ports");
Console.WriteLine("3. Allow traffic only from trusted sources");
Console.WriteLine("4. Scan IP range");
Console.WriteLine("5. Exit");
Console.Write("Select an option: ");

var option = Console.ReadLine();

switch (option)
{
    case "1":
        Console.Write("Enter the IP address or range to block (e.g., 192.168.1.100 or 192.168.1.0/24): ");
        var blockIp = Console.ReadLine();
        TrafficBlocker.BlockTrafficFromIp(blockIp);
        break;
    case "2":
        Console.Write("Enter the port(s) to restrict (e.g., 80, 443): ");
        var ports = Console.ReadLine();
        TrafficBlocker.RestrictPorts(ports);
        break;
    case "3":
        Console.Write("Enter the trusted IP address or range (e.g., 192.168.1.0/24): ");
        var trustedIp = Console.ReadLine();
        TrafficBlocker.AllowTrustedSources(trustedIp);
        break;
    case "4":
        Console.Write("Enter the IP range to scan (e.g., 192.168.1.1-192.168.1.255): ");
        var range = Console.ReadLine();
        Console.Write("Enter the ports to scan (e.g., 20-100): ");
        var portRange = Console.ReadLine();
        IpScanner.ScanIpRange(range, portRange);
        break;
    case "5":
        Console.WriteLine("Exiting...");
        return;
    default:
        Console.WriteLine("Invalid option. Exiting...");
        return;
}

Console.WriteLine("Operation completed.");
Console.ReadKey();
