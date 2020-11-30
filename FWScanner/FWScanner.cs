using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.ComponentModel;
using NetFwTypeLib;

/* Scan for all firewalls and report info */



namespace FWScanner
{
    public class Scanner
    {
        public static IScanResult Scan()
        {
            ScanResult Result = new ScanResult();
            // Windows Firewall
            Result.WinFW = WinFwScan();
            // Third-Party Firewalls
            Result.TPFWs = TPFWScan();
            return Result;
        }
        private static List<IThirdPartyFirewall> TPFWScan()
        /* 3rd party firewalls are registered in SecurityCenter2 within WMI, stored as instances of the 
        * FirewallProduct class. They can be retrieved using an instance of the ManagementObjectSearcher class, 
        * constructed using a ManagementScope object and an ObjectQuery object as constructor args. 
        * All of these classes are in the System.Management namespace
        */
        {
            List<IThirdPartyFirewall> TPFWs = new List<IThirdPartyFirewall>();

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
                    TPFWs.Add(TPFW);
                }
            }

            return TPFWs;

        }

        private static IWindowsFirewall WinFwScan()
        /* 
        * Windows Firewall information can be found using the INetFwMgr interface in the NetFwTypeLib namespace.
        * The firewall manager object, HNetCfg.FwMgr, is a COM object; type is retrieved at runtime and instantiated
        * using Activator.CreateInstance()
        */

        /* Each firewall rule in the Windows Firewall has associated remote ports.
         * This subroutine handles retrieving them, and storing them in the WinFW object in the
         * scan result. The WinFW object has a RulesByPort dict that allows looking up
         * what rules are associated with any given port (i.e. GetRulesByPort(string PortNumber))
         * See the ConsoleApp in this solution for a usage example.
         * 
         * The RemotePorts property in INetFwRule is just a string; it has comma-separated ports,
         * some actually using alphabetical names instead of numbers. This gets pulled out into
         * a list of strings, so that a program using ports 80 and 443 can be found via
         * GetRulesByPort("80") or GetRulesByPort("443")
         */
        {
            WindowsFirewall WinFW = new WindowsFirewall();

            //Instantiate Firewall Manager object and get current profile
            Type tNetFirewall = Type.GetTypeFromProgID("HNetCfg.FwMgr", false);
            INetFwMgr FwMgr = (INetFwMgr)Activator.CreateInstance(tNetFirewall);
            INetFwProfile FwProfile = FwMgr.LocalPolicy.CurrentProfile;

            // Populate basic properties
            WinFW.Enabled = FwProfile.FirewallEnabled;
            WinFW.GloballyOpenPorts = new List<IGloballyOpenPort>();
            Console.WriteLine(FwProfile.GloballyOpenPorts.Count);
  
            foreach (INetFwOpenPort p in FwProfile.GloballyOpenPorts)
            {
                GloballyOpenPort NewPort = new GloballyOpenPort
                {
                    Name = p.Name,
                    Port = p.Port,
                    Enabled = p.Enabled,
                    IpVersion = p.IpVersion,
                    IpProtocol = (Scanner.IP_PROTOCOL)p.Protocol,
                    RemoteAddresses = p.RemoteAddresses,
                };
            }

            //Get Rule objects
            Type tFwPolicy = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", false);
            INetFwPolicy2 FwPolicy = (INetFwPolicy2)Activator.CreateInstance(tFwPolicy);
            INetFwRules FwRules = FwPolicy.Rules;

            // Create a new rule for each rule object, pass it to the AddRule method of the 
            // WinFW object
            foreach (INetFwRule Rule in FwRules)
            {
                WinFWRule R = new WinFWRule();
                R.Name = Rule.Name;
                R.Description = Rule.Description;
                R.ApplicationName = Rule.ApplicationName;
                R.ServiceName = Rule.serviceName;
                R.Enabled = Rule.Enabled;
                R.RemotePorts = new List<string>();
                if (Rule.RemotePorts != null)
                {
                    //Separate by commas
                    R.RemotePorts.AddRange(Rule.RemotePorts.Split(','));
                }
                WinFW.AddRule(R);
            }

            return WinFW;
        }

        public interface IScanResult
        {
            IWindowsFirewall WinFW { get;}
            List<IThirdPartyFirewall> TPFWs { get; set; }

        }
        private class ScanResult : IScanResult
        {
            public IWindowsFirewall WinFW { get; set; }
            public List<IThirdPartyFirewall> TPFWs { get; set; }
        }
        
        public enum IP_PROTOCOL
            // these constants are the same as the protocol enum in NetFwTypeLib
        {
            TCP = 6,
            UDP = 17,
            ANY = 256
        }

        public enum IP_VERSON
        {
            V4 = 0,
            V6 = 1,
            ANY = 2,
            MAX = 3
        }

        public interface IGloballyOpenPort
        {
            string Name { get; }
            int Port { get; }
            bool Enabled { get; }
            bool BuiltIn { get; }
            string RemoteAddresses { get; }
            IP_PROTOCOL IpProtocol { get; }
            NET_FW_IP_VERSION_ IpVersion { get; }

        }

        private class GloballyOpenPort : IGloballyOpenPort
        {
            public string Name { get; set; }
            public int Port { get; set; }
            public bool Enabled { get; set; }
            public bool BuiltIn { get; set; }
            public string RemoteAddresses { get; set; }
            public IP_PROTOCOL IpProtocol { get; set; }
            public NET_FW_IP_VERSION_ IpVersion { get; set; }
        }

        public interface IWindowsFirewall
        {
            bool Enabled { get; set; }
            List<IGloballyOpenPort> GloballyOpenPorts { get; set; }
            List<IWinFWRule> GetAllRules();
            List<IWinFWRule> GetRulesByPort(string PortNumber);
        }

        private class WindowsFirewall : IWindowsFirewall
        {
            public WindowsFirewall()
            {
                this.AllRules = new List<IWinFWRule>();
                this.RulesByPort = new Dictionary<string, List<IWinFWRule>>();
            }
            public bool Enabled { get; set; }
            public List<IGloballyOpenPort> GloballyOpenPorts { get; set; }
            private List<IWinFWRule> AllRules { get; set; }
            internal void AddRule(WinFWRule NewRule)
            {
                this.AllRules.Add(NewRule);
                foreach (string P in NewRule.RemotePorts)
                {
                    if (!RulesByPort.ContainsKey(P))
                    {
                        RulesByPort[P] = new List<IWinFWRule>();
                    }
                    RulesByPort[P].Add(NewRule);
                }
            }
            public List<IWinFWRule> GetAllRules()
            {
                return AllRules;
            }
            private Dictionary<string, List<IWinFWRule>> RulesByPort { get; set; }

            public List<IWinFWRule> GetRulesByPort(string portNumber)
            {
                return RulesByPort[portNumber];
            }
        }

        public interface IWinFWRule
        {
            string Name { get; }
            string Description { get; }
            string ApplicationName { get; }
            string ServiceName { get; }
            bool Enabled { get; }
            List<string> LocalPorts { get; }
            List<string> RemotePorts { get; }
        }

        private class WinFWRule : IWinFWRule
        {
            public string Name { get; set; }
            public string Description { get; set; }
            public string ApplicationName { get; set; }
            public string ServiceName { get; set; }
            public bool Enabled { get; set; }
            public List<string> LocalPorts { get; set; }
            public List<string> RemotePorts { get; set; }
        }

        public interface IThirdPartyFirewall
        {
            string displayName { get; }
            string pathToSignedProductExe { get; }
            UInt32 productState { get; }
        }
        private class ThirdPartyFirewall : IThirdPartyFirewall
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
        // I added this testing method before adding the ConsoleApp that uses this module, kept it in here anyway..
        // It doesn't actually use the full functionality of the module, maybe don't use it for now?
        {
            public static void Run()
            {
                // Run scan and print results to console

                IScanResult FWScan = Scan();
                string WinFWStatus = FWScan.WinFW.Enabled ? "Enabled" : "Disabled";

                Console.WriteLine("Windows Firewall:");
                Console.WriteLine("    Status: {0}", WinFWStatus);

                if (FWScan.WinFW.GloballyOpenPorts.Count > 0)
                {
                    Console.WriteLine("    Open ports detected:");
                    foreach (IGloballyOpenPort Port in FWScan.WinFW.GloballyOpenPorts)
                    {
                        Console.WriteLine(Port);
                    }
                }
                else
                {
                    Console.WriteLine("    No open ports detected.");
                }

                Console.WriteLine("\n\n");

                int TPFWCount = FWScan.TPFWs.Count;
                Console.WriteLine("{0} Third-Party Firewall(s) detected.", TPFWCount);

                if (TPFWCount > 0)
                {
                    foreach (ThirdPartyFirewall TPFW in FWScan.TPFWs)
                    {
                        Console.WriteLine("\nThird Party Firewall:\n===============");
                        foreach (PropertyDescriptor Descriptor in TypeDescriptor.GetProperties(TPFW))
                        {
                            Console.WriteLine("{0}: {1}", Descriptor.Name, Descriptor.GetValue(TPFW));
                        }
                    }
                }
                //Uncomment next line for debugging in VS -- keeps console open
                //Console.ReadLine();
            }
        }
    }

    
}