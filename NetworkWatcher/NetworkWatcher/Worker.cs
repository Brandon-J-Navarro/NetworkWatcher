using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Net.NetworkInformation;
using System;
using PacketDotNet;
using SharpPcap;

namespace NetworkWatcher
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                //_logger.LogInformation("Worker running at: {time}", DateTimeOffset.Now);
                SynPacketSniffer();
                await Task.Delay(1000, stoppingToken);
            }
        }

        static void SynPacketSniffer()
        {
            // Need to install npcap or a wpcap dll dependancy error will be thrown
            try
            {
                // Get a list of all available devices
                var devices = CaptureDeviceList.Instance;

                if (devices.Count < 1)
                {
                    Console.WriteLine("No devices found on this machine.");
                    return;
                }

                // Select the first network device for monitoring
                var device = devices[8];
                Console.WriteLine($"Listening on {device.Description}...");

                // Open the device for packet capture
                device.Open(DeviceModes.Promiscuous, 1000);

                // Set up the packet arrival event handler
                device.OnPacketArrival += new PacketArrivalEventHandler(OnPacketArrival);

                // Start the packet capture
                device.StartCapture();
                Console.WriteLine("Press Enter to stop...");
                Console.ReadLine();

                // Stop capturing
                device.StopCapture();
                device.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        private static void OnPacketArrival(object sender, PacketCapture e)
        {
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.Data.ToArray());
            var tcpPacket = packet.Extract<TcpPacket>();

            if (tcpPacket != null)
            {
                if (tcpPacket.Synchronize && !tcpPacket.Acknowledgment) // SYN flag set, ACK not set
                {
                    // Need to figure out how to drill down to tcpPacket.ParentPacket.SourceAddress and tcpPacket.ParentPacket.DestinationAddress
                    Console.WriteLine($"SYN packet detected: {tcpPacket.ParentPacket}:{tcpPacket.SourcePort} -> {tcpPacket.ParentPacket}:{tcpPacket.DestinationPort}");
                }
            }
        }
    }
}