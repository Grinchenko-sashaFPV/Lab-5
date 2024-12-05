using SharpPcap;
using PacketDotNet;
using System.Collections.Concurrent;
using System.Timers;

ConcurrentDictionary<string, int> PacketCountBySource = new(); // Кількість пакетів від джерел
ConcurrentDictionary<string, ConcurrentBag<int>> PortsScannedBySource = new(); // Порти, які сканує джерело
System.Timers.Timer AnalysisTimer = new(2000); // Таймер для аналізу

Console.WriteLine("Available devices:");

var devices = CaptureDeviceList.Instance;
if (devices.Count < 1)
{
    Console.WriteLine("No devices found!");
    return;
}

for (int i = 0; i < devices.Count; i++)
    Console.WriteLine($"{i}: {devices[i].Description}");

Console.Write("Select the device number to capture traffic: ");
int deviceIndex = int.Parse(Console.ReadLine() ?? "0");

if (deviceIndex < 0 || deviceIndex >= devices.Count)
{
    Console.WriteLine("Invalid device number!");
    return;
}

var device = devices[deviceIndex];
device.OnPacketArrival += Device_OnPacketArrival;

AnalysisTimer.Elapsed += AnalyzeTrafficPatterns;
AnalysisTimer.Start();

device.Open(DeviceMode.Promiscuous, 1000);
Console.WriteLine($"Listening on {device.Description}...");

device.StartCapture();

Console.WriteLine("Press 'Enter' to stop...");
Console.ReadLine();

AnalysisTimer.Stop();
device.StopCapture();
device.Close();

void Device_OnPacketArrival(object sender, CaptureEventArgs e)
{
    try
    {
        var rawPacket = e.Packet;
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

        if (packet is EthernetPacket ethernetPacket)
        {
            var ipPacket = ethernetPacket.PayloadPacket as IpPacket;
            if (ipPacket != null)
            {
                var sourceIp = ipPacket.SourceAddress.ToString();
                PacketCountBySource.AddOrUpdate(sourceIp, 1, (_, count) => count + 1);

                if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
                {
                    var destinationPort = tcpPacket.DestinationPort;
                    PortsScannedBySource.AddOrUpdate(
                        sourceIp,
                        _ => new ConcurrentBag<int> { destinationPort },
                        (_, ports) =>
                        {
                            ports.Add(destinationPort);
                            return ports;
                        });
                }
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error processing packet: {ex.Message}");
    }
}

void AnalyzeTrafficPatterns(object sender, ElapsedEventArgs e)
{
    Console.WriteLine("Analyzing traffic patterns...");

    foreach (var (sourceIp, count) in PacketCountBySource)
    {
        // Поріг для великої кількості пакетів (типу DDoS)
        if (count > 1000)
        {
            Console.WriteLine($"[WARNING] Possible DDoS attack from {sourceIp}: {count} packets detected!");
        }
    }

    foreach (var (sourceIp, ports) in PortsScannedBySource)
    {
        var distinctPorts = ports.Distinct().ToList();
        // Поріг для сканування портів
        if (distinctPorts.Count > 5)
        {
            Console.WriteLine($"[WARNING] Port scanning detected from {sourceIp}: {distinctPorts.Count} ports scanned!");
        }
    }

    // Очищуємо статистику для наступного аналізу
    PacketCountBySource.Clear();
    PortsScannedBySource.Clear();
}
