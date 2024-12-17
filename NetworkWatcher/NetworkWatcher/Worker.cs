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
                //TCPServer();
                //NetTCPListener();
                //ShowStatistics(NetworkInterfaceComponent.IPv4);
                //ShowStatistics(NetworkInterfaceComponent.IPv6);
                //PacketSniffer();
                SynPacketSniffer();
                await Task.Delay(1000, stoppingToken);
            }
        }

        //public async void NetTCPListener()
        //{


        //    try
        //    {
        //        //var ipEndPoint = new IPEndPoint(IPAddress.Any, 80);
        //        TcpListener listener = new TcpListener(IPAddress.Any, 0);
        //        listener.Start();

        //        //using TcpClient handler = await listener.AcceptTcpClientAsync();
        //        //await using NetworkStream stream = handler.GetStream();

        //        //var message = $"📅 {DateTime.Now} 🕛";
        //        //var dateTimeBytes = Encoding.UTF8.GetBytes(message);
        //        //await stream.WriteAsync(dateTimeBytes);

        //        //Console.WriteLine($"Sent message: \"{message}\"");
        //        // Sample output:
        //        //     Sent message: "📅 8/22/2022 9:07:17 AM 🕛"
        //        listener.Stop();
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine($"{ex.Message}");
        //    }
        //}

        //public void TCPServer()
        //{
        //    try
        //    {
        //        TcpListener myList = new TcpListener(IPAddress.Any, 8010);
        //        myList.Start();

        //        Console.WriteLine("Server running at port 8001...");
        //        Console.WriteLine("Waiting for a connection...");

        //        Socket s = myList.AcceptSocket();
        //        Console.WriteLine("Connection accepted from " + s.RemoteEndPoint);

        //        byte[] b = new byte[100];
        //        int k = s.Receive(b);
        //        Console.WriteLine("Recieved...");
        //        for (int i = 0; i < k; i++)
        //            Console.Write(Convert.ToChar(b[i]));

        //        ASCIIEncoding asen = new ASCIIEncoding();
        //        s.Send(asen.GetBytes("The string was recieved by the server."));
        //        Console.WriteLine("\nSent Acknowledgement");
        //        /* clean up */
        //        s.Close();
        //        Console.Read();
        //        myList.Stop();

        //    }
        //    catch (Exception e)
        //    {
        //        Console.WriteLine("Error: " + e.StackTrace);
        //        Console.Read();
        //    }
        //}

        //static void ShowStatistics(NetworkInterfaceComponent version)
        //{
        //    var properties = IPGlobalProperties.GetIPGlobalProperties();
        //    var stats = version switch
        //    {
        //        NetworkInterfaceComponent.IPv4 => properties.GetTcpIPv4Statistics(),
        //        _ => properties.GetTcpIPv6Statistics()
        //    };

        //    Console.WriteLine($"TCP/{version} Statistics");
        //    Console.WriteLine($"  Minimum Transmission Timeout : {stats.MinimumTransmissionTimeout:#,#}");
        //    Console.WriteLine($"  Maximum Transmission Timeout : {stats.MaximumTransmissionTimeout:#,#}");
        //    Console.WriteLine("  Connection Data");
        //    Console.WriteLine($"      Current :                  {stats.CurrentConnections:#,#}");
        //    Console.WriteLine($"      Cumulative :               {stats.CumulativeConnections:#,#}");
        //    Console.WriteLine($"      Initiated  :               {stats.ConnectionsInitiated:#,#}");
        //    Console.WriteLine($"      Accepted :                 {stats.ConnectionsAccepted:#,#}");
        //    Console.WriteLine($"      Failed Attempts :          {stats.FailedConnectionAttempts:#,#}");
        //    Console.WriteLine($"      Reset :                    {stats.ResetConnections:#,#}");
        //    Console.WriteLine("  Segment Data");
        //    Console.WriteLine($"      Received :                 {stats.SegmentsReceived:#,#}");
        //    Console.WriteLine($"      Sent :                     {stats.SegmentsSent:#,#}");
        //    Console.WriteLine($"      Retransmitted :            {stats.SegmentsResent:#,#}");
        //    Console.WriteLine();
        //}

        //static void PacketSniffer()
        //{
        //    try
        //    {
        //        // Create a raw socket for IPv4
        //        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

        //        // Bind the socket to all IP addresses on the local machine
        //        socket.Bind(new IPEndPoint(IPAddress.Any, 0));

        //        // Set the socket to receive all incoming IP packets
        //        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

        //        // Enable packet reception (capture IP packets)
        //        byte[] inValue = new byte[4] { 1, 0, 0, 0 };
        //        byte[] outValue = new byte[4];
        //        socket.IOControl(IOControlCode.ReceiveAll, inValue, outValue);

        //        Console.WriteLine("Listening for incoming SYN packets...");

        //        byte[] buffer = new byte[4096];

        //        while (true)
        //        {
        //            // Receive incoming packets
        //            int receivedBytes = socket.Receive(buffer);
        //            Console.WriteLine("Packet received");

        //            // Parse the IP packet and TCP header to detect SYN flags
        //            if (IsSynPacket(buffer, receivedBytes))
        //            {
        //                Console.WriteLine("SYN packet detected.");
        //            }
        //        }
        //    }
        //    catch(Exception ex)
        //    {
        //        Console.WriteLine(ex);
        //    }
        //}

        //static bool IsSynPacket(byte[] buffer, int size)
        //{
        //    if (size < 20) return false; // Ensure packet is large enough for an IP header

        //    // IP Header (Assuming IPv4, without options)
        //    int ipHeaderLength = (buffer[0] & 0x0F) * 4;

        //    // Check if it's TCP (Protocol 6 in IP header)
        //    byte protocol = buffer[9];
        //    if (protocol != 6) return false; // Not a TCP packet

        //    // TCP Header starts after IP Header
        //    int tcpHeaderOffset = ipHeaderLength;

        //    // TCP Flags are in the 14th byte of the TCP header
        //    byte flags = buffer[tcpHeaderOffset + 13];

        //    // Check for SYN flag (0x02)
        //    return (flags & 0x02) != 0 && (flags & 0x10) == 0; // SYN set, ACK not set
        //}



        static void SynPacketSniffer()
        {
            // Get a list of all available devices
            var devices = CaptureDeviceList.Instance;

            if (devices.Count < 1)
            {
                Console.WriteLine("No devices found on this machine.");
                return;
            }

            // Select the first network device for monitoring
            var device = devices[0];
            Console.WriteLine($"Listening on {device.Description}...");

            // Open the device for packet capture
            device.Open(DeviceModes.Promiscuous, 1000);

            // Set up the packet arrival event handler
            //device.OnPacketArrival += new PacketArrivalEventHandler(OnPacketArrival);

            // Start the packet capture
            device.StartCapture();
            Console.WriteLine("Press Enter to stop...");
            Console.ReadLine();

            // Stop capturing
            device.StopCapture();
            device.Close();
        }

        //private static void OnPacketArrival(object sender, PacketCapture e)
        //{
        //    var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.Data);
        //    var tcpPacket = packet.Extract<TcpPacket>();

        //    if (tcpPacket != null)
        //    {
        //        if (tcpPacket.Synchronize && !tcpPacket.Acknowledgment) // SYN flag set, ACK not set
        //        {
        //            Console.WriteLine($"SYN packet detected: {tcpPacket}:{tcpPacket.SourcePort} -> {tcpPacket}:{tcpPacket.DestinationPort}");
        //        }
        //    }
        //}
    }
}