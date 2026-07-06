# Situational Awareness
## Network Information
We should always look at **routing tables** to view information about the local network and networks around it. We can also gather information about the local domain (if the host is part of an Active Directory environment), including the IP addresses of domain controllers. It is also important to use the **arp** command to view the ARP cache for each interface and view other hosts the host has recently communicated with.

### Interface(s), IP Address(es), DNS Information

```cmd
C:\htb> ipconfig /all
```

### ARP Table

```cmd
C:\htb> arp -a
```

### Routing Table

```cmd
C:\htb> route print
```

## Enumerating Protections
### Check Windows Defender Status

```cmd
PS C:\htb> Get-MpComputerStatus
```

### List AppLocker Rules

```cmd
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### Test AppLocker Policy

```cmd
PS C:\htb> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone

FilePath                    PolicyDecision MatchingRule
--------                    -------------- ------------
C:\Windows\System32\cmd.exe         Denied c:\windows\system32\cmd.exe
```

## Questions
RDP to 10.129.43.43 (ACADEMY-WINLPE-SRV01), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. What is the IP address of the other NIC attached to the target host? **Answer: 172.16.20.45**
   - Run `ipconfig` to view the `Ethernet1` adapter:
        ```cmd
        > ipconfig /all

        Windows IP Configuration

        Host Name . . . . . . . . . . . . : WINLPE-SRV01
        Primary Dns Suffix  . . . . . . . :
        Node Type . . . . . . . . . . . . : Hybrid
        IP Routing Enabled. . . . . . . . : No
        WINS Proxy Enabled. . . . . . . . : No
        DNS Suffix Search List. . . . . . : htb

        Ethernet adapter Ethernet1:

        Connection-specific DNS Suffix  . :
        Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
        Physical Address. . . . . . . . . : A2-DE-AD-71-30-FC
        DHCP Enabled. . . . . . . . . . . : No
        Autoconfiguration Enabled . . . . : Yes
        Link-local IPv6 Address . . . . . : fe80::7d26:a48d:2849:c858%2(Preferred)
        IPv4 Address. . . . . . . . . . . : 172.16.20.45(Preferred)
        Subnet Mask . . . . . . . . . . . : 255.255.254.0
        Default Gateway . . . . . . . . . : 172.16.20.1
        DHCPv6 IAID . . . . . . . . . . . : 151015510
        DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-31-DD-2A-21-A2-DE-AD-71-30-FC
        DNS Servers . . . . . . . . . . . : 8.8.8.8
        NetBIOS over Tcpip. . . . . . . . : Enabled
        ```
2. What executable other than cmd.exe is blocked by AppLocker? **Answer: powershell_ise.exe**
   - Check for AppLocker policy, look for the `Action: Deny` section:
        ```pwsh
        > Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

        <SNIP>

        PathConditions      : {%SYSTEM32%\WindowsPowerShell\v1.0\powershell_ise.exe}
        PathExceptions      : {}
        PublisherExceptions : {}
        HashExceptions      : {}
        Id                  : 684d8b3e-7656-4451-8abe-2588d772db8f
        Name                : Block PowerShell ISE
        Description         :
        UserOrGroupSid      : S-1-1-0
        Action              : Deny
        ```