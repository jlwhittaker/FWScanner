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
            Scanner.IScanResult Result = Scanner.Scan();

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
