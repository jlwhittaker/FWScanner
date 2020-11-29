using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FWScanner;

namespace ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Run scan and get result
            Scanner.IScanResult Result = Scanner.Scan();

            // Print WinFW information
            Console.WriteLine("Windows Firewall:");
            Console.WriteLine($"    Status: {(Result.WinFW.Enabled ? "Enabled" : "Disabled")}");
            Console.WriteLine($"    {Result.WinFW.GloballyOpenPorts.Count} globally open ports found.\n");

            // Find application names by port
            Console.WriteLine("Applications using port 80:");
            foreach (string AppName in GetAppNameByPort("80",Result.WinFW))
            {
                Console.WriteLine(AppName);
            }
            Console.WriteLine("\n\nApplications using port 443:");
            foreach (string AppName in GetAppNameByPort("443", Result.WinFW))
            {
                Console.WriteLine(AppName);
            }
            Console.WriteLine();

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

            //Debugging; use to keep console open
            Console.ReadLine();
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
    }
}
