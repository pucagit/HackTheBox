# SMNP (port 161,162)
It is a protocol for monitoring and managing network devices. SNMP also transmits control commands using agents over UDP port **161**. 

SNMP also enables the use of so-called **traps** over UDP port **162**. These are data packets sent from the SNMP server to the client without being explicitly requested. If a device is configured accordingly, an SNMP trap is sent to the client once a specific event occurs on the server-side.

For the SNMP client and server to exchange the respective values, the available SNMP objects must have unique addresses known on both sides. 

## MIB
To ensure that SNMP access works across manufacturers and with different client-server combinations, the Management Information Base (MIB) was created. MIB is an independent format for storing device information. A MIB is a text file in which all queryable SNMP objects of a device are listed in a standardized tree hierarchy. It contains at least one Object Identifier (OID), which, in addition to the necessary unique address and a name, also provides information about the type, access rights, and a description of the respective object. MIB files are written in the Abstract Syntax Notation One (ASN.1) based ASCII text format. The MIBs do not contain data, but they explain where to find which information and what it looks like, which returns values for the specific OID, or which data type is used.

## OID
An OID represents a node in a hierarchical namespace. A sequence of numbers uniquely identifies each node, allowing the node's position in the tree to be determined. The longer the chain, the more specific the information. Many nodes in the OID tree contain nothing except references to those below them. The OIDs consist of integers and are usually concatenated by dot notation. We can look up many MIBs for the associated OIDs in the **Object Identifier Registry**.

## SNMPv1
SNMPv1 has no built-in authentication mechanism, meaning anyone accessing the network can read and modify network data. Another main flaw of SNMPv1 is that it does not support encryption, meaning that all data is sent in plain text and can be easily intercepted.

## SNMPv2
The version still exists today is `v2c`, and the extension `c` means community-based SNMP. Significant problem with the initial execution of the SNMP protocol is that the **community string** (can be seen as passwords that are used to determine whether the requested information can be viewed or not) that provides security is only transmitted in plain text, meaning it has no built-in encryption.

## SNMPv3
The security has been increased enormously for SNMPv3 by security features such as authentication using username and password and transmission encryption (via pre-shared key) of the data. 

## Default Configuration
```
$ cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'

sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>
sysServices    72
master  agentx
agentaddress  127.0.0.1,[::1]
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
```

## Dangerous Settings
|Setting|Description|
|-|-|
|`rwuser noauth`|Provides access to the full OID tree without authentication.|
|`rwcommunity <community string> <IPv4 address>`|Provides access to the full OID tree regardless of where the requests were sent from.|
|`rwcommunity6 <community string> <IPv6 address>`|Same access as with `rwcommunity` with the difference of using IPv6.|

## Footpringting
### SNMPWalk
Snmpwalk is used to query the OIDs with their information.
```
$ snmpwalk -v2c -c <community string> <ip>
```
### Onesixtyone
Onesixtyone can be used to brute-force the names of the community strings since they can be named arbitrarily by the administrator. 
```
$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt <ip>
```
### Braa
Once we know a community string, we can use it with braa to brute-force the individual OIDs and enumerate the information behind them.
```
$ braa <community string>@<IP>:.1.3.6.*
```
## Questions
1. Enumerate the SNMP service and obtain the email address of the admin. Submit it as the answer. **Answer: devadmin@inlanefreight.htb**
   - `$ snmpwalk -v2c -c public <ip>` -> read the response: `iso.3.6.1.2.1.1.4.0 = STRING: "devadmin <devadmin@inlanefreight.htb>"`
2. What is the customized version of the SNMP server? **Answer: InFreight SNMP v0.91**
   - `$ snmpwalk -v2c -c public <ip>` -> read the response: `iso.3.6.1.2.1.1.6.0 = STRING: "InFreight SNMP v0.91"`
3. Enumerate the custom script that is running on the system and submit its output as the answer. **Answer: HTB{5nMp_fl4g_uidhfljnsldiuhbfsdij44738b2u763g}**
   - `$ snmpwalk -v2c -c public <ip>` -> read the response 
```
iso.3.6.1.2.1.25.1.7.1.2.1.2.4.70.76.65.71 = STRING: "/usr/share/flag.sh"
iso.3.6.1.2.1.25.1.7.1.2.1.3.4.70.76.65.71 = ""
iso.3.6.1.2.1.25.1.7.1.2.1.4.4.70.76.65.71 = ""
iso.3.6.1.2.1.25.1.7.1.2.1.5.4.70.76.65.71 = INTEGER: 5
iso.3.6.1.2.1.25.1.7.1.2.1.6.4.70.76.65.71 = INTEGER: 1
iso.3.6.1.2.1.25.1.7.1.2.1.7.4.70.76.65.71 = INTEGER: 1
iso.3.6.1.2.1.25.1.7.1.2.1.20.4.70.76.65.71 = INTEGER: 4
iso.3.6.1.2.1.25.1.7.1.2.1.21.4.70.76.65.71 = INTEGER: 1
iso.3.6.1.2.1.25.1.7.1.3.1.1.4.70.76.65.71 = STRING: "HTB{5nMp_fl4g_uidhfljnsldiuhbfsdij44738b2u763g}"
```
## Cheat sheet / mapping table for the most useful SNMP Host Resources MIB (hrMIB) OIDs under `.1.3.6.1.2.1.25.*`.
| OID Branch | Name                          | Description               | Example Data                  |
| ---------- | ----------------------------- | ------------------------- | ----------------------------- |
| **.25.1**  | **hrSystem**                  | General system info       | Uptime, number of users       |
| .25.1.1    | hrSystemUptime                | Time since last boot      | `10:12:46.78`                 |
| .25.1.2    | hrSystemDate                  | Current date/time         | `2021-09-14 14:43:45`         |
| .25.1.3    | hrSystemInitialLoadDevice     | Boot device               | Disk/Partition ID             |
| .25.1.4    | hrSystemInitialLoadParameters | Boot parameters           | `BOOT_IMAGE=/boot/vmlinuz...` |
| .25.1.5    | hrSystemNumUsers              | Number of logged-in users | `3`                           |
| .25.1.6    | hrSystemProcesses             | Number of processes       | `411`                         |
| .25.1.7    | hrSystemMaxProcesses          | Max processes allowed     | Value depends on OS           |
| **.25.2**   | **hrStorage**            | Storage devices info | Mounted disks, RAM   |
| .25.2.3.1.3 | hrStorageDescr           | Storage description  | `/`, `/boot`, `/tmp` |
| .25.2.3.1.4 | hrStorageAllocationUnits | Block size           | `4096 bytes`         |
| .25.2.3.1.5 | hrStorageSize            | Total size           | `500000 blocks`      |
| .25.2.3.1.6 | hrStorageUsed            | Used space           | `250000 blocks`      |
| **.25.3** | **hrDevice** | Hardware devices | CPUs, disks, network cards |
| .25.3.2.1.3 | hrDeviceDescr | Device description | `"Intel(R) Xeon CPU"` |
| .25.3.2.1.5 | hrDeviceStatus | Device state | Running / Idle / Down |
| **.25.4** | **hrSWRun** | Running software/processes | Similar to ps |
| .25.4.2.1.2 | hrSWRunName | Process name | `"sshd"`, `"nginx"` |
| .25.4.2.1.4 | hrSWRunPath | Executable path | `"/usr/sbin/sshd"` |
| .25.4.2.1.5 | hrSWRunParameters | Command-line args | `"-D"` |
| .25.4.2.1.6 | hrSWRunType | Process type | `operatingSystem`, `application` |
| .25.4.2.1.7 | hrSWRunStatus | Process status | `running(1)` |
| **.25.5** | **hrSWRunPerf** | Performance per process | CPU & memory stats |
| .25.6.3.1.2 | hrSWInstalledName | Installed package name | `"python3"`, `"nginx"` |
| .25.6.3.1.3 | hrSWInstalledDate | Install date | `2021-09-01` |
| .25.6 | hrSWInstalled | Installed software list | Like `dpkg -l` / `rpm -qa` |
| .25.6.3.1.2 | hrSWInstalledName | Installed package name | `"python3"`, `"nginx"` |
| .25.6.3.1.3 | hrSWInstalledDate | Install date | `2021-09-01` |