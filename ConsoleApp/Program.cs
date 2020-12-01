using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FWScanner;
using NetFwTypeLib;


namespace ConsoleApp
{
    class Program
    {
        static INetFwProfile FwProfile;
        const string OpenPortGuid = "{0CA545C6-37AD-4A6C-BF92-9F7610067EF5}";
        static void Main(string[] args)
        {
            // Set up Fw Profile
            FwProfile = FWSetup();

            //First Test
            Console.WriteLine("Running FW scan test...\n");
            ScanTest();

            //Open port and test again
            int PortNumber = 8989;
            Console.WriteLine("\nAttempting to open global port, using port {0}", PortNumber);
            if (OpenPort(PortNumber))
            {
                Console.WriteLine("Successfully opened port {0}", PortNumber);
                Console.WriteLine("Attempting another scan...\n\n");
                ScanTest();

                // Close port and test again
                Console.WriteLine("Attempting to close port {0}", PortNumber);
                if (ClosePort(PortNumber))
                {
                    Console.WriteLine("Successfully closed port {0}", PortNumber);
                    Console.WriteLine("Attempting another scan...\n\n");
                    ScanTest();
                }
                else
                // Not sure why closing the port would fail if opening worked, but here it is
                {
                    Console.WriteLine("Could not close port {0}", PortNumber);

                }
            }
            else
            {
                Console.WriteLine("Could not open port {0}", PortNumber);
            }
            //Debugging; use to keep console open
            Console.ReadLine();
        }

        static void ScanTest()
        {
            // Run scan and get result
            Scanner.IScanResult Result = Scanner.Scan();

            // Print WinFW information
            Console.WriteLine("Windows Firewall:");
            Console.WriteLine($"    Status: {(Result.WinFW.Enabled ? "Enabled" : "Disabled")}");
            Console.WriteLine($"    {Result.WinFW.GloballyOpenPorts.Count} globally open port(s) found.\n");

            // Find application names by port
            Console.WriteLine("Applications using port 80:");
            foreach (string AppName in GetAppNameByPort("80", Result.WinFW))
            {
                Console.WriteLine(AppName);
            }
            Console.WriteLine("\n\nApplications using port 443:");
            foreach (string AppName in GetAppNameByPort("443", Result.WinFW))
            {
                Console.WriteLine(AppName);
            }
            Console.WriteLine("\n\n");

            // Print list of third party firewalls
            if (Result.TPFWs.Count > 0)
            {
                Console.WriteLine("Third-party firewalls detected\n=========");
            }
            foreach (Scanner.IThirdPartyFirewall TPFW in Result.TPFWs)
            {
                Console.WriteLine("Name: {0}", TPFW.displayName);
                Console.WriteLine("Status Code: {0}", TPFW.productState);
            }
            Console.WriteLine("\n\n\n");
        }
        static List<string> GetAppNameByPort(string PortNumber, Scanner.IWindowsFirewall FW)
        {
            List<Scanner.IWinFWRule> Rules = FW.GetRulesByPort(PortNumber);
            List<string> AppNames = new List<string>();
            foreach (Scanner.IWinFWRule Rule in Rules)
            {
                AppNames.Add(Rule.ApplicationName);
            }
            return AppNames;
        }

        static bool OpenPort(int PortNumber)
        // Open a global port to ensure that the Windows Firewall Scan picks it up
        {
            // Get instance of open port object
            Type tOpenPort = Type.GetTypeFromCLSID(new Guid(OpenPortGuid));
            INetFwOpenPort OpenPort = (INetFwOpenPort)Activator.CreateInstance(tOpenPort);

            // port config
            OpenPort.Protocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
            OpenPort.Name = "Testing Port";
            OpenPort.Port = PortNumber;

            // Add port
            INetFwOpenPorts OpenPorts = FwProfile.GloballyOpenPorts;
            try
            {
                OpenPorts.Add(OpenPort);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.GetType().FullName);
                return false;
            }
        }

        static bool ClosePort(int PortNumber)
        {
            INetFwOpenPorts OpenPorts = FwProfile.GloballyOpenPorts;
            try
            {
                OpenPorts.Remove(PortNumber, NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP);
                return true;
            }
            catch
            {
                return false;
            }
        }

        static INetFwProfile FWSetup()
        {
            // Get FW profile
            Type tNetFirewall = Type.GetTypeFromProgID("HNetCfg.FwMgr");
            INetFwMgr FwMgr = (INetFwMgr)Activator.CreateInstance(tNetFirewall);
            return FwMgr.LocalPolicy.CurrentProfile;
        }

    }
}
