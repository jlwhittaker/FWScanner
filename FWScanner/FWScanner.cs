using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.ComponentModel;

/* Scan for all 3rd party firewalls and report info */

/* 3rd party firewalls are registered in SecurityCenter2 within WMI, stored as instances of the 
 * FirewallProduct class. They can be retrieved using an instance of the ManagementObjectSearcher class, 
 * constructed using a ManagementScope object and an ObjectQuery object as constructor args. 
 * All of these classes are in the System.Management namespace
 */

namespace FWScanner
{
    class FWScanner
    {
        public static List<Firewall> Scan()
        {
            List<Firewall> ScanResult = new List<Firewall>();

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
                    Firewall Result = new Firewall();

                    foreach (PropertyData Property in FW.Properties)
                    {
                        //This line works because of direct mapping between Firewall and WMI object properties
                        Result.GetType().GetProperty(Property.Name).SetValue(Result, Property.Value);
                    }

                    ScanResult.Add(Result);
                }
            }
            else
            {
                ScanResult = null;
            }
            
            return ScanResult;
        }

    }

    class Firewall
    // Properties are 1 to 1 match for properties in WMI object, not sure if good idea or not
    {
        public string displayName { get; set; }
        public string instanceGuid { get; set; }
        public string pathToSignedProductExe { get; set; }
        public string pathToSignedReportingExe { get; set; }
        public UInt32 productState { get; set; }
        public string timestamp { get; set; }
    }

    class Program
    {
        static void Main(string[] args)
        {
            List<Firewall> ScanResults = FWScanner.Scan();

            if (ScanResults != null)
            {
                foreach (Firewall Result in ScanResults)
                {
                    Console.WriteLine("Firewall Found:");
                    Console.WriteLine("===============");

                    foreach (PropertyDescriptor Descriptor in TypeDescriptor.GetProperties(Result))
                    {
                        Console.WriteLine("{0}: {1}", Descriptor.Name, Descriptor.GetValue(Result));
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