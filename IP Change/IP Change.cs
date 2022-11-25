﻿using ManagedNativeWifi;
using Newtonsoft.Json;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;

namespace IP_Change
{
	class Program
	{
		static bool _debug = false;

		#region Constant Variable
		static readonly string _WIRED = "Wired";
		static readonly string _WIRELESS = "Wireless";

		static readonly string _DHCP = "DHCP";
		static readonly string _FIX = "Fix";
		static readonly string _AUTO = "Auto";

		static readonly Hashtable SetDnsReturnValue = new Hashtable()
		{
			  { 0, "Successful completion, no reboot required" }
			, { 1, "Successful completion, reboot required" }
			, { 64, "Method not supported on this platform" }
			, { 65, "Unknown failure" }
			, { 66, "Invalid subnet mask" }
			, { 67, "An error occurred while processing an Instance that was returned" }
			, { 68, "Invalid input parameter" }
			, { 69, "More than 5 gateways specified" }
			, { 70, "Invalid IP  address" }
			, { 71, "Invalid gateway IP address" }
			, { 72, "An error occurred while accessing the Registry for the requested information" }
			, { 73, "Invalid domain name" }
			, { 74, "Invalid host name" }
			, { 75, "No primary/secondary WINS server defined" }
			, { 76, "Invalid file" }
			, { 77, "Invalid system path" }
			, { 78, "File copy failed" }
			, { 79, "Invalid security parameter" }
			, { 80, "Unable to configure TCP/IP service" }
			, { 81, "Unable to configure DHCP service" }
			, { 82, "Unable to renew DHCP lease" }
			, { 83, "Unable to release DHCP lease" }
			, { 84, "IP not enabled on adapter" }
			, { 85, "IPX not enabled on adapter" }
			, { 86, "Frame/network number bounds error" }
			, { 87, "Invalid frame type" }
			, { 88, "Invalid network number" }
			, { 89, "Duplicate network number" }
			, { 90, "Parameter out of bounds" }
			, { 91, "Access denied" }
			, { 92, "Out of memory" }
			, { 93, "Already exists" }
			, { 94, "Path, file or object not found" }
			, { 95, "Unable to notify service" }
			, { 96, "Unable to notify DNS service" }
			, { 97, "Interface not configurable" }
			, { 98, "Not all DHCP leases could be released/renewed" }
			, { 100, "DHCP not enabled on adapter" }
		};
		#endregion

		#region Adapter Variable
		class Config
		{
			[DefaultValue(false)]
			[JsonProperty(DefaultValueHandling = DefaultValueHandling.Populate)]
			public bool dhcp { get; set; }
			public string ip { get; set; }
			public string subnet { get; set; }
			public string gateway { get; set; }

			[DefaultValue(1)]
			[JsonProperty(DefaultValueHandling = DefaultValueHandling.Populate)]
			public int metric { get; set; }
			public string dns { get; set; }
		}

		class Adapter
		{
			public string name { get; set; }
			public string ssid { get; set; }
			public Config config { get; set; }
		}

		class Networks
		{
			List<Adapter> networkList = new List<Adapter>();

			public int selectedAdapterIndex { get; set; }
			public int selectedInterfaceIndex { get; set; }
			public List<Adapter> networks { get { return networkList; } set { networkList = value; } }
		}

		static Networks AdapterList = new Networks();

		static int choosetAdapterIndex = 0;
		#endregion

		#region Interface Variable
		class Interface
		{
			public string guid { get; set; }
			public string name { get; set; }
			public string deviceID { get; set; }
			public string netConnectionID { get; set; }
			public int index { get; set; }
			public int interfaceIndex { get; set; }
			public string macAddr { get; set; }
			public int typeId { get; set; }
			public bool netEnabled { get; set; }
			public bool physicalAdapter { get; set; }
		}

		static List<Interface> InterfaceList = new List<Interface>();

		static int chooseInterfaceIndex = 0;
		#endregion

		static string MessageFromHResult(int hr)
		{
			return Marshal.GetExceptionForHR(hr).Message;
		}

		static bool IsContains(string keyword, string[] ContainList, bool caseIgnore = false)
		{
			foreach (string word in ContainList)
			{
				if (caseIgnore)
				{
					if (keyword.ToUpper().Contains(word.ToUpper())) return true;
				}
				else
				{
					if (keyword.Contains(word)) return true;
				}
			}

			return false;
		}

		static bool IsWirelessInterface(string infId)
		{
			if (infId.First().Equals('{') && infId.Last().Equals('}'))
			{
				infId = infId.Substring(1, infId.Length - 2).ToLower();
			}

			foreach (InterfaceInfo infInfo in NativeWifi.EnumerateInterfaces())
			{
				if (infInfo.Id.ToString().Equals(infId))
				{
					return true;
				}
			}

			return false;
		}

		static void SetWiredAdapter(Adapter adpCfg, Interface infCfg)
		{
			string NamespacePath = "\\\\.\\ROOT\\cimv2";
			string ClassName = "Win32_NetworkAdapterConfiguration"; // PS> Get-WmiObject Win32_NetworkAdapterConfiguration | Get-Member
			string mesg = null;

			Console.WriteLine("Change Wired Interface...");

			mesg = ""
				+ "name: " + adpCfg.name
				+ ", dhcp: " + (adpCfg.config.dhcp ? _DHCP : _FIX)
				+ ", ip: " + (adpCfg.config.dhcp ? _AUTO : adpCfg.config.ip)
				+ ", subnet: " + (adpCfg.config.dhcp ? _AUTO : adpCfg.config.subnet)
				+ ", gateway: " + (adpCfg.config.dhcp ? _AUTO : adpCfg.config.gateway)
				+ ", dns: " + (adpCfg.config.dhcp ? _AUTO : adpCfg.config.dns)
			;
			if (_debug) Console.WriteLine("  - {0}", mesg);

			ManagementClass mngtClass = new ManagementClass(NamespacePath + ":" + ClassName);

			if (_debug) Console.WriteLine("  + index, caption, mac");

			foreach (ManagementObject mngtObj in mngtClass.GetInstances())
			{
				var index = Convert.ToInt32(mngtObj["Index"]);
				string caption = (string)mngtObj["Caption"];
				string macAddr = (string.IsNullOrEmpty((string)mngtObj["MACAddress"]) ? string.Empty : ((string)mngtObj["MACAddress"]).Replace(':', '-'));

				if (_debug) Console.WriteLine("  > {0}, {1}, {2}", index, caption, macAddr);

				if (index == infCfg.index && macAddr.Equals(infCfg.macAddr))
				{
					bool netEnabled = false, ipEnabled = false;

					if (adpCfg.config.dhcp)
					{
						// ***********************************************************************
						// set dhcp
						// ***********************************************************************
						//wmiObject.InvokeMethod("Enable", null);
						Console.WriteLine("DHCP Enable");
					}
					else
					{
						// ***********************************************************************
						// set static
						// ***********************************************************************
						ManagementBaseObject inMngtBaseObj = null, outMngtBaseObj = null;
						uint retCode = 0;

						string[] ipAddress = new string[] { adpCfg.config.ip };
						string[] subnetMask = new string[] { adpCfg.config.subnet };
						string[] defaultIPGateway = new string[] { adpCfg.config.gateway };
						int[] gatewayCostMetric = new int[] { adpCfg.config.metric };
						string[] dns = adpCfg.config.dns.Split(';');

						Console.WriteLine("    -> IP: {0}, SUBNET: {1}, G/W: {2}, DNS: {3}", string.Join(";", ipAddress), string.Join(";", subnetMask), string.Join(";", defaultIPGateway), string.Join(";", dns));

						#region Network Enabled
						Console.Write("       Network Enabled");

						// get value
						netEnabled = infCfg.netEnabled;
						Console.Write(String.Empty.PadLeft(20, '.'));

						if (netEnabled)
						{
							Console.WriteLine("OK");
						}
						else
						{
							Console.WriteLine("({0}) Fail: This adapter is not enabled", netEnabled);
						}
						#endregion

						#region IP Enabled
						Console.Write("       IP Enabled");

						// get value
						ipEnabled = Convert.ToBoolean(mngtObj["IPEnabled"]);
						Console.Write(String.Empty.PadLeft(25, '.'));

						if (ipEnabled)
						{
							Console.WriteLine("OK");
						}
						else
						{
							Console.WriteLine("({0}) Fail: TCP/IP is not bound and enabled on this network adapter", ipEnabled);
						}
						#endregion

						#region IP/Subnet
						Console.Write("       IP/Subnet");

						// get method
						inMngtBaseObj = mngtObj.GetMethodParameters("EnableStatic");
						Console.Write(".");

						// set value
						inMngtBaseObj["IPAddress"] = ipAddress;
						inMngtBaseObj["SubnetMask"] = subnetMask;
						Console.Write(".");

						// apply method
						outMngtBaseObj = mngtObj.InvokeMethod("EnableStatic", inMngtBaseObj, null);
						Console.Write(".");

						retCode = Convert.ToUInt32(outMngtBaseObj["ReturnValue"]);
						Console.Write(String.Empty.PadLeft(23, '.'));

						if (retCode == 0)
						{
							Console.WriteLine("OK");
						}
						else
						{
							Console.WriteLine("Fail: {0}", Marshal.GetExceptionForHR((int)retCode).Message);
						}
						#endregion

						#region Gateway
						Console.Write("       Gateways");

						// get method
						inMngtBaseObj = mngtObj.GetMethodParameters("SetGateways");
						Console.Write(".");

						// set value
						inMngtBaseObj["DefaultIPGateway"] = defaultIPGateway;
						inMngtBaseObj["GatewayCostMetric"] = gatewayCostMetric;
						Console.Write(".");

						// apply method
						outMngtBaseObj = mngtObj.InvokeMethod("SetGateways", inMngtBaseObj, null);
						Console.Write(".");

						retCode = Convert.ToUInt32(outMngtBaseObj["ReturnValue"]);
						Console.Write(String.Empty.PadLeft(24, '.'));

						if (retCode == 0)
						{
							Console.WriteLine("OK");
						}
						else
						{
							Console.WriteLine("Fail: {0}", Marshal.GetExceptionForHR((int)retCode).Message);
						}
						#endregion

						#region DNS
						Console.Write("       DNS");

						// get method
						inMngtBaseObj = mngtObj.GetMethodParameters("SetDNSServerSearchOrder");
						Console.Write(".");

						// set value
						inMngtBaseObj["DNSServerSearchOrder"] = dns;
						Console.Write(".");

						// apply method
						outMngtBaseObj = mngtObj.InvokeMethod("SetDNSServerSearchOrder", inMngtBaseObj, null);
						Console.Write(".");

						retCode = Convert.ToUInt32(outMngtBaseObj["ReturnValue"]);
						Console.Write(String.Empty.PadLeft(29, '.'));

						if (retCode == 0)
						{
							Console.WriteLine("OK");
						}
						else
						{
							Console.Write("({0}) ", retCode);
							Console.WriteLine("Fail: {0}", SetDnsReturnValue[(int)retCode]);
						}
						#endregion
					}

					break;
				}
			}
		}

		static void SetWirelessdAdapter(Adapter adpCfg, Interface infCfg)
		{
			Console.WriteLine("Change Wirelessd Interface...");
		}

		public static void Main(string[] args)
		{
			#region Set Arguments
			if (args.Length > 0)
			{
				for (int idx = 0; idx < args.Length; idx++)
				{
					string arg = args[idx];

					switch (arg.Substring(0, 2).ToUpper())
					{
						case "-D": // debug
							_debug = true;
							break;
						case "-I": // network interface
							try { chooseInterfaceIndex = int.Parse(arg.Substring(2)); } catch { }
							break;
						case "-C": // adapter config
							try { choosetAdapterIndex = int.Parse(arg.Substring(2)); } catch { }
							break;
					}
				}

				if (_debug)
				{
					Console.WriteLine("set debugging: {0}", _debug);
					Console.WriteLine("chooseInterfaceIndex: {0}", chooseInterfaceIndex);
					Console.WriteLine("choosetAdapterIndex: {0}", choosetAdapterIndex);
					Console.WriteLine();
				}
			}
			#endregion

			#region Load Adapters Config
			try
			{
				if (_debug) Console.WriteLine("Load Adapters Config...");

				AdapterList = JsonConvert.DeserializeObject<Networks>(File.ReadAllText("IP Change.json"));

				if (_debug) {
					int idx = 1;

					if (_debug) Console.WriteLine("  - adapterList count: {0}", AdapterList.networks.Count);
					if (_debug) Console.WriteLine("  + idx, name, ssid, dhcp, ip");

					foreach (Adapter adapter in AdapterList.networks)
					{
						string mesg = "  > " + (idx++)
							+ " " + adapter.name
							+ ", " + (string.IsNullOrEmpty(adapter.ssid) ? "local" : adapter.ssid)
							+ ", " + (adapter.config.dhcp ? _DHCP : _FIX)
							+ ", " + (adapter.config.dhcp ? _AUTO : adapter.config.ip)
						;
						Console.WriteLine(mesg);
					}
				}

				if (AdapterList == null || AdapterList.networks.Count() == 0)
				{
					Console.WriteLine("The config file has some problem...");
					return;
				}
			}
			catch (Exception e)
			{
				Console.WriteLine(e.Message);
				return;
			}

			if (_debug) Console.WriteLine();
			#endregion

			#region Retrieve Network Interface
			try
			{
				int idx = 1;
				string NamespacePath = "\\\\.\\ROOT\\cimv2";
				string ClassName = "Win32_NetworkAdapter"; // PS> Get-WmiObject Win32_NetworkAdapter | Get-Member

				ManagementClass mngtClass = new ManagementClass(NamespacePath + ":" + ClassName);

				if (_debug) Console.WriteLine("Retrieve Network Interface...");
				if (_debug) Console.WriteLine($"  + guid, name, index, interfaceIndex, macAddr, typeId, netEnabled, physicalAdapter");

				foreach (ManagementObject mngtObj in mngtClass.GetInstances())
				{
					string guid = (string)mngtObj["GUID"];
					string name = (string)mngtObj["Name"];
					string deviceID = (string)mngtObj["DeviceID"];
					string netConnectionID = (string)mngtObj["NetConnectionID"];
					int index = Convert.ToInt32(mngtObj["Index"]);
					int interfaceIndex = Convert.ToInt32(mngtObj["InterfaceIndex"]);
					string macAddr = (string.IsNullOrEmpty((string)mngtObj["MACAddress"]) ? string.Empty : ((string)mngtObj["MACAddress"]).Replace(':', '-'));
					int typeId = Convert.ToInt16(mngtObj["AdapterTypeID"]);
					bool netEnabled = Convert.ToBoolean(mngtObj["NetEnabled"]);
					bool physicalAdapter = Convert.ToBoolean(mngtObj["PhysicalAdapter"]);

					if (_debug) Console.Write($"  > {guid}, {name}, {deviceID}, {netConnectionID}, {index}, {interfaceIndex}, {macAddr}, {typeId}, {netEnabled}, {physicalAdapter}");

					if (string.IsNullOrEmpty(guid) == false && index > 0 && string.IsNullOrEmpty(macAddr) == false && physicalAdapter)
					{
						InterfaceList.Add(new Interface() {
							  guid = guid
							, name = name
							, deviceID = deviceID
							, netConnectionID = netConnectionID
							, index = index
							, interfaceIndex = interfaceIndex
							, macAddr = macAddr
							, typeId = typeId
							, netEnabled = netEnabled
						});
						if (_debug) Console.Write($" -> added, {idx++}");
					}

					if (_debug) Console.WriteLine();
				}
			}
			catch (Exception e)
			{
				Console.WriteLine(e.Message);
				return;
			}

			if (_debug) Console.WriteLine();
			#endregion

			#region Select Network Interface
			if (InterfaceList.Count > 1 && chooseInterfaceIndex == 0)
			{
				string mesg = null, userInput = null;
				int chooseValue = 0;

				while (true)
				{
					Console.WriteLine("Enter a number to select the network interfaces.");

					for (int idx = 0; idx < InterfaceList.Count(); idx++)
					{
						mesg = "    "
							+ "[" + (idx + 1) + "]"
							+ " " + InterfaceList[idx].name
							+ ", " + InterfaceList[idx].macAddr
							+ ", " + InterfaceList[idx].index
						;
						Console.WriteLine(mesg);
					}

					Console.Write("  Choose: ");

					userInput = Console.ReadLine();

					try
					{
						chooseValue = int.Parse(userInput);
					}
					catch
					{
						chooseValue = 0;
					}

					if (chooseValue > 0 && chooseValue <= InterfaceList.Count())
					{
						chooseInterfaceIndex = chooseValue;
						break;
					}
					else
					{
						Console.WriteLine();
					}
				}
			}
			else
			{
				if (InterfaceList.Count == 1 && chooseInterfaceIndex == 0)
				{
					chooseInterfaceIndex = 1;
				}

				string mesg = "Select the network interfaces: "
					+ "[" + (chooseInterfaceIndex) + "]"
					+ " " + InterfaceList[chooseInterfaceIndex - 1].name
					+ " : " + InterfaceList[chooseInterfaceIndex - 1].macAddr
					+ ", " + InterfaceList[chooseInterfaceIndex - 1].index
				;
				Console.WriteLine(mesg);
			}

			Console.WriteLine();
			#endregion

			#region Select Adapters Config
			if (AdapterList.networks.Count > 1 && choosetAdapterIndex == 0)
			{
				string mesg = null, userInput = null;
				int chooseValue = 0;

				while (true)
				{
					Console.WriteLine("Enter a number to select the networks config.");

					for (int idx = 0; idx < AdapterList.networks.Count(); idx++)
					{
						mesg = "    "
							+ "[" + (idx + 1) + "]"
							+ " " + AdapterList.networks[idx].name
							+ " : " + (AdapterList.networks[idx].ssid == null ? _WIRED : _WIRELESS)
							+ ", " + (AdapterList.networks[idx].config.dhcp ? _DHCP : _FIX)
							+ ", " + (AdapterList.networks[idx].config.dhcp ? _AUTO : AdapterList.networks[idx].config.ip)
						;
						Console.WriteLine(mesg);
					}

					Console.Write("  Choose: ");

					userInput = Console.ReadLine();

					try
					{
						chooseValue = int.Parse(userInput);
					}
					catch
					{
						chooseValue = 0;
					}

					if (chooseValue > 0 && chooseValue <= AdapterList.networks.Count())
					{
						choosetAdapterIndex = chooseValue;
						break;
					}
					else
					{
						Console.WriteLine();
					}
				}
			}
			else
			{
				if (AdapterList.networks.Count > 1 && choosetAdapterIndex == 0)
				{
					choosetAdapterIndex = 1;
				}

				string mesg = "Select the networks config: "
					+ "[" + choosetAdapterIndex + "]"
					+ " " + AdapterList.networks[choosetAdapterIndex - 1].name
					+ " : " + (AdapterList.networks[choosetAdapterIndex - 1].ssid == null ? _WIRED : _WIRELESS)
					+ ", " + (AdapterList.networks[choosetAdapterIndex - 1].config.dhcp ? _DHCP : _FIX)
					+ ", " + (AdapterList.networks[choosetAdapterIndex - 1].config.dhcp ? _AUTO : AdapterList.networks[choosetAdapterIndex - 1].config.ip)
				;
				Console.WriteLine(mesg);
			}

			Console.WriteLine();
			#endregion

			#region Change Adapters Config to Network Interface
			Adapter adpCfg = AdapterList.networks[choosetAdapterIndex - 1];
			Interface infCfg = InterfaceList[chooseInterfaceIndex - 1];
			bool isWireless = false;

			if (_debug) Console.WriteLine("[CFG] name: {0}", adpCfg.name);

			isWireless = IsWirelessInterface(infCfg.guid);
			if (_debug) Console.WriteLine("[INF] id: {0}, name: {1}, mac: {2}, type: {3}", infCfg.guid, infCfg.name, infCfg.macAddr, (isWireless ? _WIRELESS : _WIRED));

			if (isWireless)
			{
				SetWirelessdAdapter(adpCfg, infCfg);
			}
			else
			{
				SetWiredAdapter(adpCfg, infCfg);
			}

			Console.WriteLine();
			#endregion
		}
	}
}