using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.ComponentModel;
using NetFwTypeLib;

/* Scan for all 3rd party firewalls and report info */

/* 
 * Windows Firewall information can be found using the INetFwMgr interface in the NetFwTypeLib namespace.
 * The firewall manager object, HNetCfg.FwMgr, is a COM object; type is retrieved at runtime and instantiated
 * using Activator.CreateInstance()

 * 3rd party firewalls are registered in SecurityCenter2 within WMI, stored as instances of the 
 * FirewallProduct class. They can be retrieved using an instance of the ManagementObjectSearcher class, 
 * constructed using a ManagementScope object and an ObjectQuery object as constructor args. 
 * All of these classes are in the System.Management namespace
 */

namespace FWScanner
{
    public class FWScanner
    {
        public static ScanResult Scan()
        {
            ScanResult Result = new ScanResult();

            // Windows Firewall

            //Instantiate Firewall Manager object and get current profile
            Type tNetFirewall = Type.GetTypeFromProgID("HNetCfg.FwMgr", false);
            INetFwMgr FwMgr = (INetFwMgr)Activator.CreateInstance(tNetFirewall);
            INetFwProfile FwProfile = FwMgr.LocalPolicy.CurrentProfile;
            
            // Populate return object
            Result.WinFW = new WindowsFirewall
            {
                Enabled = FwProfile.FirewallEnabled,
                OpenPorts = new List<int>()
            };

            foreach (int port in FwProfile.GloballyOpenPorts)
            {
                Result.WinFW.OpenPorts.Add(port);
            }

            // Third Party Firewalls 

            Result.TPFWs = new List<ThirdPartyFirewall>();

            // Set up scope for WMI
            ManagementScope Scope = new ManagementScope("\\\\localhost\\root\\SecurityCenter2", null);
            Scope.Connect();

            // Prepare query and create searcher
            ObjectQuery Query = new ObjectQuery("SELECT * FROM FirewallProduct");
            ManagementObjectSearcher Searcher = new ManagementObjectSearcher(Scope, Query);

            // Populate list of firewalls found (if any)
            if (Searcher.Get().Count > 0)
            {
                foreach (ManagementObject FW in Searcher.Get())
                {
                    ThirdPartyFirewall TPFW = new ThirdPartyFirewall();

                    foreach (PropertyData Property in FW.Properties)
                    {
                        //This line works because of direct mapping between Firewall and WMI object properties
                        TPFW.GetType().GetProperty(Property.Name).SetValue(TPFW, Property.Value);
                    }
                    Result.TPFWs.Add(TPFW);
                }    
            }
            return Result;
        }

    }

    public class ScanResult
    {
        public WindowsFirewall WinFW { get; set; }
        public List<ThirdPartyFirewall> TPFWs { get; set; }
    }

    public class WindowsFirewall
    {
        public bool Enabled { get; set; }
        public List<int> OpenPorts { get; set; }
    }

    public class ThirdPartyFirewall
    // Properties are 1 to 1 match for properties in WMI object, not sure if good idea or not
    {
        public string displayName { get; set; }
        public string instanceGuid { get; set; }
        public string pathToSignedProductExe { get; set; }
        public string pathToSignedReportingExe { get; set; }
        public UInt32 productState { get; set; }
        public string timestamp { get; set; }
    }

    public class FwScanTest
    {
        static void Main(string[] args)
        {
            // Run scan and print results to console

            ScanResult FWScan = FWScanner.Scan();
            string WinFWStatus = FWScan.WinFW.Enabled ? "Enabled" : "Disabled";

            Console.WriteLine("Windows Firewall:");
            Console.WriteLine("    Status: {0}", WinFWStatus);

            if (FWScan.WinFW.OpenPorts.Count > 0)
            {
                Console.WriteLine("    Open ports detected:");
                foreach ( int Port in FWScan.WinFW.OpenPorts)
                {
                    Console.WriteLine(Port);
                }
            }
            else
            {
                Console.WriteLine("    No open ports detected.");
            }
            Console.WriteLine();

            if (FWScan.TPFWs.Count > 0)
            {
                Console.WriteLine("No Third-Party Firewalls detected.");
                foreach (ThirdPartyFirewall TPFW in FWScan.TPFWs)
                {
                    Console.WriteLine();
                    Console.WriteLine("Third Party Firewall:");
                    Console.WriteLine("===============");

                    foreach (PropertyDescriptor Descriptor in TypeDescriptor.GetProperties(TPFW))
                    {
                        Console.WriteLine("{0}: {1}", Descriptor.Name, Descriptor.GetValue(TPFW));
                    }
                }
            }
            else
            {
                Console.WriteLine("No Firewalls Detected.");
            }
            //Uncomment next line for debugging in VS -- keeps console open
            //Console.ReadLine();
        }
    }
}