# Initial Enumeration
We can escalate privileges to one of the following depending on the system configuration and what type of data we encounter:

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">The highly privileged <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">NT AUTHORITY\SYSTEM</code> account, or <a href="https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account" rel="nofollow" target="_blank" class="hover:underline text-green-400">LocalSystem</a> account which is a highly privileged account with more privileges than a local administrator account and is used to run most Windows services.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">The built-in local <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">administrator</code> account. Some organizations disable this account, but many do not. It is not uncommon to see this account reused across multiple systems in a client environment.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Another local account that is a member of the local <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Administrators</code> group. Any account in this group will have the same privileges as the built-in <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">administrator</code> account.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">A standard (non-privileged) domain user who is part of the local <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Administrators</code> group.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">A domain admin (highly privileged in the Active Directory environment) that is part of the local <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Administrators</code> group.</td></tr></tbody></table>

## System Information
### Tasklist
Using the tasklist command to look at running processes will give us a better idea of what applications are currently running on the system.

```cmd
C:\htb> tasklist /svc
```

It is essential to become familiar with standard Windows processes such as **Session Manager Subsystem (smss.exe)**,** Client Server Runtime Subsystem (csrss.exe)**, **WinLogon (winlogon.exe)**, **Local Security Authority Subsystem Service (LSASS)**, and **Service Host (svchost.exe)**, among others and the services associated with them.

### Display All Environment Variables
When running a program, Windows looks for that program in the CWD (Current Working Directory) first, then from the `PATH` going left to right. This means if the custom path is placed on the left (before `C:\Windows\System32`), it is much more dangerous than on the right.

```cmd
C:\htb> set

ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\Administrator\AppData\Roaming
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=WINLPE-SRV01
ComSpec=C:\Windows\system32\cmd.exe
HOMEDRIVE=C:
HOMEPATH=\Users\Administrator
LOCALAPPDATA=C:\Users\Administrator\AppData\Local
LOGONSERVER=\\WINLPE-SRV01
NUMBER_OF_PROCESSORS=6
OS=Windows_NT
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD
PROCESSOR_LEVEL=23
PROCESSOR_REVISION=3100
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC=C:\Users\Public
SESSIONNAME=Console
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Users\ADMINI~1\AppData\Local\Temp\1
TMP=C:\Users\ADMINI~1\AppData\Local\Temp\1
USERDOMAIN=WINLPE-SRV01
USERDOMAIN_ROAMINGPROFILE=WINLPE-SRV01
USERNAME=Administrator
USERPROFILE=C:\Users\Administrator
windir=C:\Windows
```

### View Detailed Configuration Information
The `systeminfo` command will show if the box has been patched recently and if it is a VM.

```cmd
C:\htb> systeminfo

Host Name:                 WINLPE-SRV01
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00376-30000-00299-AA303
Original Install Date:     3/24/2021, 3:46:32 PM
System Boot Time:          3/25/2021, 9:24:36 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              3 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [03]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     6,143 MB
Available Physical Memory: 3,474 MB
Virtual Memory: Max Size:  10,371 MB
Virtual Memory: Available: 7,544 MB
Virtual Memory: In Use:    2,827 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\WINLPE-SRV01
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB3199986
                           [02]: KB5001078
                           [03]: KB4103723
Network Card(s):           2 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.43.8
                                 [02]: fe80::e4db:5ea3:2775:8d4d
                                 [03]: dead:beef::e4db:5ea3:2775:8d4d
                           [02]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet1
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.20.56
                                 [02]: fe80::f055:fefd:b1b:9919
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

### Patches and Updates
If `systeminfo` doesn't display hotfixes, they may be queriable with WMI using the WMI-Command binary with [QFE (Quick Fix Engineering)](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering) to display patches.

```cmd
C:\htb> wmic qfe

Caption                                     CSName        Description      FixComments  HotFixID   InstallDate  InstalledBy          InstalledOn  Name  ServicePackInEffect  Status
http://support.microsoft.com/?kbid=3199986  WINLPE-SRV01  Update                        KB3199986               NT AUTHORITY\SYSTEM  11/21/2016
https://support.microsoft.com/help/5001078  WINLPE-SRV01  Security Update               KB5001078               NT AUTHORITY\SYSTEM  3/25/2021
http://support.microsoft.com/?kbid=4103723  WINLPE-SRV01  Security Update               KB4103723               NT AUTHORITY\SYSTEM  3/25/2021
```

We can do this with PowerShell as well using the Get-Hotfix cmdlet.

```pwsh
PS C:\htb> Get-HotFix | ft -AutoSize

Source       Description     HotFixID  InstalledBy                InstalledOn
------       -----------     --------  -----------                -----------
WINLPE-SRV01 Update          KB3199986 NT AUTHORITY\SYSTEM        11/21/2016 12:00:00 AM
WINLPE-SRV01 Update          KB4054590 WINLPE-SRV01\Administrator 3/30/2021 12:00:00 AM
WINLPE-SRV01 Security Update KB5001078 NT AUTHORITY\SYSTEM        3/25/2021 12:00:00 AM
WINLPE-SRV01 Security Update KB3200970 WINLPE-SRV01\Administrator 4/13/2021 12:00:00 AM
```

### Installed Programs

```cmd
C:\htb> wmic product get name

Name
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.24.28127
Java 8 Update 231 (64-bit)
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127
VMware Tools
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.24.28127
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127
Java Auto Updater

<SNIP>
```

We can, of course, do this with PowerShell as well using the Get-WmiObject cmdlet.

```pwsh
PS C:\htb> Get-WmiObject -Class Win32_Product |  select Name, Version

Name                                                                    Version
----                                                                    -------
SQL Server 2016 Database Engine Shared                                  13.2.5026.0
Microsoft OLE DB Driver for SQL Server                                  18.3.0.0
Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219             10.0.40219
Microsoft Help Viewer 2.3                                               2.3.28107
Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219             10.0.40219
Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.21005              12.0.21005
Microsoft Visual C++ 2013 x86 Additional Runtime - 12.0.21005           12.0.21005
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29914          14.28.29914
Microsoft ODBC Driver 13 for SQL Server                                 13.2.5026.0
SQL Server 2016 Database Engine Shared                                  13.2.5026.0
SQL Server 2016 Database Engine Services                                13.2.5026.0
SQL Server Management Studio for Reporting Services                     15.0.18369.0
Microsoft SQL Server 2008 Setup Support Files                           10.3.5500.0
SSMS Post Install Tasks                                                 15.0.18369.0
Microsoft VSS Writer for SQL Server 2016                                13.2.5026.0
Java 8 Update 231 (64-bit)                                              8.0.2310.11
Browser for SQL Server 2016                                             13.2.5026.0
Integration Services                                                    15.0.2000.130

<SNIP>
```

### Display Running Processes

```pwsh
PS C:\htb> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       1096
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       840
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3520
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       968
<...SNIP...>
```

## User & Group Information
### Logged-In Users

```cmd
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>administrator         rdp-tcp#2           1  Active          .  3/25/2021 9:27 AM
```

### Current User
Suppose we gain access as a service account. In that case, we may have privileges such as `SeImpersonatePrivilege`, which can often be easily abused to escalate privileges using a tool such as [Juicy Potato](https://github.com/ohpe/juicy-potato).

```cmd
C:\htb> echo %USERNAME%

htb-student
```

### Current User Privileges

```cmd
C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

### Current User Group Information

```cmd
C:\htb> whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON  Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

### Get All Users

```cmd
C:\htb> net user

User accounts for \\WINLPE-SRV01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
helpdesk                 htb-student              jordan
sarah                    secsvc
The command completed successfully.
```

### Get All Groups

```cmd
C:\htb> net localgroup

Aliases for \\WINLPE-SRV01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Certificate Service DCOM Access
*Cryptographic Operators
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Print Operators
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Storage Replica Administrators
*System Managed Accounts Group
*Users
The command completed successfully.
```

### Details About a Group
Though unlikely, we may find a password or other interesting information stored in the group's description. 

```cmd
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
helpdesk
sarah
secsvc
The command completed successfully.
```

### Get Password Policy & Other Account Information

```cmd
C:\htb> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
```

## Questions
RDP to 10.129.43.43 (ACADEMY-WINLPE-SRV01), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. What non-default privilege does the htb-student user have? **Answer: SeTakeOwnershipPrivilege**
   - Run this command in a elevated cmd session:
        ```cmd
        C:\Windows\system32>whoami /priv

        PRIVILEGES INFORMATION
        ----------------------

        Privilege Name                Description                              State
        ============================= ======================================== ========
        SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
        SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
        SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
        ```
2. Who is a member of the Backup Operators group? **Answer: sarah**
   - Check with `net localgroup` command:
        ```cmd
        C:\Windows\system32>net localgroup

        Aliases for \\WINLPE-SRV01

        -------------------------------------------------------------------------------
        *Access Control Assistance Operators
        *Administrators
        *Backup Operators
        *Certificate Service DCOM Access
        *Cryptographic Operators
        *Distributed COM Users
        *Event Log Readers
        *Guests
        *Hyper-V Administrators
        *IIS_IUSRS
        *Network Configuration Operators
        *Performance Log Users
        *Performance Monitor Users
        *Power Users
        *Print Operators
        *RDS Endpoint Servers
        *RDS Management Servers
        *RDS Remote Access Servers
        *Remote Desktop Users
        *Remote Management Users
        *Replicator
        *SQLServer2005SQLBrowserUser$WINLPE-SRV01
        *Storage Replica Administrators
        *System Managed Accounts Group
        *Users
        The command completed successfully.


        C:\Windows\system32>net localgroup "Backup Operators"
        Alias name     Backup Operators
        Comment        Backup Operators can override security restrictions for the sole purpose of backing up or restoring files

        Members

        -------------------------------------------------------------------------------
        sarah
        The command completed successfully.
        ```
3. What service is listening on port 8080 (service name not the executable)? **Answer: Tomcat8**
   - Check which process ID is listening on port 8080:
        ```cmd
        C:\Windows\system32>netstat -ano | findstr 8080
        TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       2352
        TCP    [::]:8080              [::]:0                 LISTENING       2352
        ```
   - Find that process:
        ```cmd
        C:\Windows\system32>tasklist /svc | findstr 2352
        Tomcat8.exe                   2352 Tomcat8
        ```
4. What user is logged in to the target host? **Answer: sccm_svc**
   - Query logged in users:
        ```cmd
        C:\Windows\system32>query user
        USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
        sccm_svc              console             1  Active      none   7/6/2026 2:14 AM
        >htb-student           rdp-tcp#0           2  Active          .  7/6/2026 2:17 AM
        ```
5. What type of session does this user have? **Answer: console**
   - In the above command output