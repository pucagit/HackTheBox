# External Information Gathering
## Questions
1. Perform a banner grab of the services listening on the target host and find a non-standard service banner. Submit the name as your answer (format: word_word_word) **Answer: 1337_HTB_DNS**
   - Perform a full port nmap scan with banner grabbing script:
        ```shellsession
        $ sudo nmap -sV -A -Pn --disable-arp-ping --script banner -p- 10.129.111.175 -oA 10.129.111.175.nmap
        Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-20 06:45 EDT
        Nmap scan report for 10.129.111.175
        Host is up (0.16s latency).
        Not shown: 65524 closed tcp ports (reset)
        PORT     STATE SERVICE  VERSION
        21/tcp   open  ftp      vsftpd 3.0.3
        |_banner: 220 (vsFTPd 3.0.3)
        22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
        |_banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        25/tcp   open  smtp     Postfix smtpd
        |_banner: 220 ubuntu ESMTP Postfix (Ubuntu)
        53/tcp   open  domain   (unknown banner: 1337_HTB_DNS)
        | fingerprint-strings: 
        |   DNSVersionBindReqTCP: 
        |     version
        |     bind
        |_    1337_HTB_DNS
        80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
        |_http-server-header: Apache/2.4.41 (Ubuntu)
        110/tcp  open  pop3     Dovecot pop3d
        |_banner: +OK Dovecot (Ubuntu) ready.
        111/tcp  open  rpcbind  2-4 (RPC #100000)
        | rpcinfo: 
        |   program version    port/proto  service
        |   100000  2,3,4        111/tcp   rpcbind
        |   100000  2,3,4        111/udp   rpcbind
        |   100000  3,4          111/tcp6  rpcbind
        |_  100000  3,4          111/udp6  rpcbind
        143/tcp  open  imap     Dovecot imapd (Ubuntu)
        | banner: * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE ID
        |_LE LITERAL+ STARTTLS LOGINDISABLED] Dovecot (Ubuntu) ready.
        993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
        | banner: * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE ID
        |_LE LITERAL+ AUTH=PLAIN] Dovecot (Ubuntu) ready.
        995/tcp  open  ssl/pop3 Dovecot pop3d
        |_banner: +OK Dovecot (Ubuntu) ready.
        8080/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
        |_http-server-header: Apache/2.4.41 (Ubuntu)
        1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
        SF-Port53-TCP:V=7.95%I=7%D=7/20%Time=6A5DFCCA%P=x86_64-pc-linux-gnu%r(DNSV
        SF:ersionBindReqTCP,39,"\x007\0\x06\x85\0\0\x01\0\x01\0\0\0\0\x07version\x
        SF:04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\r\x0c1337_HTB_DNS");
        Device type: general purpose
        Running: Linux 5.X
        OS CPE: cpe:/o:linux:linux_kernel:5
        OS details: Linux 5.0 - 5.14
        Network Distance: 2 hops
        Service Info: Host:  ubuntu; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

        TRACEROUTE (using port 1720/tcp)
        HOP RTT       ADDRESS
        1   156.12 ms 10.10.14.1
        2   156.39 ms 10.129.111.175

        OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
        Nmap done: 1 IP address (1 host up) scanned in 180.67 seconds
        ```
2. Perform a DNS Zone Transfer against the target and find a flag. Submit the flag value as your answer (flag format: HTB{ }). **Answer: HTB{DNs_ZOn3_Tr@nsf3r}**
   - Perform a DNS Zone Transfer against `ilanefreight.local`:
        ```shellsession
        $ dig axfr inlanefreight.local @10.129.111.175

        ; <<>> DiG 9.20.18-1~deb13u1-Debian <<>> axfr inlanefreight.local @10.129.111.175
        ;; global options: +cmd
        inlanefreight.local.	86400	IN	SOA	ns1.inlanfreight.local. dnsadmin.inlanefreight.local. 21 604800 86400 2419200 86400
        inlanefreight.local.	86400	IN	NS	inlanefreight.local.
        inlanefreight.local.	86400	IN	A	127.0.0.1
        blog.inlanefreight.local. 86400	IN	A	127.0.0.1
        careers.inlanefreight.local. 86400 IN	A	127.0.0.1
        dev.inlanefreight.local. 86400	IN	A	127.0.0.1
        flag.inlanefreight.local. 86400	IN	TXT	"HTB{DNs_ZOn3_Tr@nsf3r}"
        gitlab.inlanefreight.local. 86400 IN	A	127.0.0.1
        ir.inlanefreight.local.	86400	IN	A	127.0.0.1
        status.inlanefreight.local. 86400 IN	A	127.0.0.1
        support.inlanefreight.local. 86400 IN	A	127.0.0.1
        tracking.inlanefreight.local. 86400 IN	A	127.0.0.1
        vpn.inlanefreight.local. 86400	IN	A	127.0.0.1
        inlanefreight.local.	86400	IN	SOA	ns1.inlanfreight.local. dnsadmin.inlanefreight.local. 21 604800 86400 2419200 86400
        ;; Query time: 173 msec
        ;; SERVER: 10.129.111.175#53(10.129.111.175) (TCP)
        ;; WHEN: Mon Jul 20 07:20:02 EDT 2026
        ;; XFR size: 14 records (messages 1, bytes 448)
        ```
3. What is the FQDN of the associated subdomain? **Answer: flag.inlanefreight.local**
   - Read the above output
4. Perform vhost discovery. What additional vhost exists? (one word) **Answer: monitoring**
   - Figure out what the response looks like for a non-existent vhost:
        ```shellsession
        $ curl -s -I 10.129.111.175 -H "HOST: 404.inlanefreight.local" | grep "Content-Length:"
        Content-Length: 15157
        ```
   - Fuzz VHOST using `ffuf`:
        ```shellsession
        $ ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://10.129.111.175 -H 'Host: FUZZ.inlanefreight.local' -fs 15157

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://10.129.111.175
        :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
        :: Header           : Host: FUZZ.inlanefreight.local
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 15157
        ________________________________________________

        blog                    [Status: 200, Size: 8708, Words: 1509, Lines: 232, Duration: 833ms]
        careers                 [Status: 200, Size: 51806, Words: 22041, Lines: 732, Duration: 173ms]
        dev                     [Status: 200, Size: 2048, Words: 643, Lines: 74, Duration: 169ms]
        gitlab                  [Status: 302, Size: 113, Words: 5, Lines: 1, Duration: 182ms]
        ir                      [Status: 200, Size: 28548, Words: 2885, Lines: 210, Duration: 1075ms]
        monitoring              [Status: 200, Size: 56, Words: 3, Lines: 4, Duration: 164ms]
        ```