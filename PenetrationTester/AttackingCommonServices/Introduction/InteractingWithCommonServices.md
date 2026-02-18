# Interacting with Common Services

## Server Message Block (SMB)
### Windows
The command `net use` connects a computer to or disconnects a computer from a shared resource or displays information about computer connections. We can connect to a file share with the following command and map its content to the drive letter `n`.

```cmd
C:\htb> net use n: \\192.168.220.129\Finance

The command completed successfully.
```

or

```pwsh
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"

Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```

We can also provide a username and password to authenticate to the share.

```cmd
C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123

The command completed successfully.
```

or

```pwsh
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
----           ---------     --------- --------      ----                                                              ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```

With the shared folder mapped as the `n` drive, we can execute Windows commands as if this shared folder is on our local computer. This command counts how many files there are in the drive:

```cmd
C:\htb> dir n: /a-d /s /b | find /c ":\"

29302
```

or

```pwsh
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

29302
```

With `dir` we can search for specific names:

```cmd
C:\htb>dir n:\*cred* /s /b

n:\Contracts\private\credentials.txt


C:\htb>dir n:\*secret* /s /b

n:\Contracts\private\secret.txt
```

or

```pwsh
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

    Directory: N:\Contracts\private

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/23/2022   4:36 PM             25 credentials.txt
```

If we want to search for a specific word within a text file, we can use `findstr`.

```cmd
c:\htb>findstr /s /i cred n:\*.*

n:\Contracts\private\secret.txt:file with all credentials
n:\Contracts\private\credentials.txt:admin:SecureCredentials!
```

or

```pwsh
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List

N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```

> **Note:** We can run both Windows commands and PowerShell cmdlets in PowerShell

### Linux
Linux (UNIX) machines can also be used to browse and mount SMB shares. 

```sh
masterofblafu@htb[/htb]$ sudo mkdir /mnt/Finance
masterofblafu@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

As an alternative, we can use a credential file.

```sh
masterofblafu@htb[/htb]$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```

The file credentialfile has to be structured like this:

```txt
username=plaintext
password=Password123
domain=.
```

> **Note:** We need to install cifs-utils to connect to an SMB share folder. To install it we can execute from the command line sudo apt install cifs-utils.

Let's hunt for a filename that contains the string `cred`:

```sh
masterofblafu@htb[/htb]$ find /mnt/Finance/ -name *cred*

/mnt/Finance/Contracts/private/credentials.txt
```

Find files that contain the string `cred`:

```sh
masterofblafu@htb[/htb]$ grep -rn /mnt/Finance/ -ie cred

/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
```

## Email
We can use a mail client such as [Evolution](https://wiki.gnome.org/Apps/Evolution), the official personal information manager, and mail client for the GNOME Desktop Environment. We can interact with an email server to send or receive messages with a mail client. To install Evolution, we can use the following command:

```sh
masterofblafu@htb[/htb]$ sudo apt-get install evolution
```

> **Note:** If an error appears when starting evolution indicating "bwrap: Can't create file at ...", use this command to start evolution `export WEBKIT_FORCE_SANDBOX=0 && evolution`.

## MSSQL
To interact with MSSQL (Microsoft SQL Server) with Linux we can use `sqsh` or `sqlcmd` if you are using Windows. We can start an interactive SQL session as follows:

```sh
masterofblafu@htb[/htb]$ sqsh -S 10.129.20.13 -U username -P Password123
```

or

```cmd
C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
```

## MySQL
To interact with MySQL, we can use MySQL binaries for Linux (mysql) or Windows (mysql.exe). 

```sh
masterofblafu@htb[/htb]$ mysql -u username -pPassword123 -h 10.129.20.13
```

or

```cmd
C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13
```

## Tools to Interact with Common Services

<table class="table table-striped text-left">
<thead>
<tr>
<th><strong>SMB</strong></th>
<th><strong>FTP</strong></th>
<th><strong>Email</strong></th>
<th><strong>Databases</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td><a href="https://www.samba.org/samba/docs/current/man-html/smbclient.1.html" target="_blank" rel="noopener nofollow">smbclient</a></td>
<td><a href="https://linux.die.net/man/1/ftp" target="_blank" rel="noopener nofollow">ftp</a></td>
<td><a href="https://www.thunderbird.net/en-US/" target="_blank" rel="noopener nofollow">Thunderbird</a></td>
<td><a href="https://github.com/dbcli/mssql-cli" target="_blank" rel="noopener nofollow">mssql-cli</a></td>
</tr>
<tr>
<td><a href="https://github.com/byt3bl33d3r/CrackMapExec" target="_blank" rel="noopener nofollow">CrackMapExec</a></td>
<td><a href="https://lftp.yar.ru/" target="_blank" rel="noopener nofollow">lftp</a></td>
<td><a href="https://www.claws-mail.org/" target="_blank" rel="noopener nofollow">Claws</a></td>
<td><a href="https://github.com/dbcli/mycli" target="_blank" rel="noopener nofollow">mycli</a></td>
</tr>
<tr>
<td><a href="https://github.com/ShawnDEvans/smbmap" target="_blank" rel="noopener nofollow">SMBMap</a></td>
<td><a href="https://www.ncftp.com/" target="_blank" rel="noopener nofollow">ncftp</a></td>
<td><a href="https://wiki.gnome.org/Apps/Geary" target="_blank" rel="noopener nofollow">Geary</a></td>
<td><a href="https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py" target="_blank" rel="noopener nofollow">mssqlclient.py</a></td>
</tr>
<tr>
<td><a href="https://github.com/SecureAuthCorp/impacket" target="_blank" rel="noopener nofollow">Impacket</a></td>
<td><a href="https://filezilla-project.org/" target="_blank" rel="noopener nofollow">filezilla</a></td>
<td><a href="https://getmailspring.com" target="_blank" rel="noopener nofollow">MailSpring</a></td>
<td><a href="https://github.com/dbeaver/dbeaver" target="_blank" rel="noopener nofollow">dbeaver</a></td>
</tr>
<tr>
<td><a href="https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py" target="_blank" rel="noopener nofollow">psexec.py</a></td>
<td><a href="http://www.crossftp.com/" target="_blank" rel="noopener nofollow">crossftp</a></td>
<td><a href="http://www.mutt.org/" target="_blank" rel="noopener nofollow">mutt</a></td>
<td><a href="https://dev.mysql.com/downloads/workbench/" target="_blank" rel="noopener nofollow">MySQL Workbench</a></td>
</tr>
<tr>
<td><a href="https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py" target="_blank" rel="noopener nofollow">smbexec.py</a></td>
<td></td>
<td><a href="https://mailutils.org/" target="_blank" rel="noopener nofollow">mailutils</a></td>
<td><a href="https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms" target="_blank" rel="noopener nofollow">SQL Server Management Studio or SSMS</a></td>
</tr>
<tr>
<td></td>
<td></td>
<td><a href="https://github.com/mogaal/sendemail" target="_blank" rel="noopener nofollow">sendEmail</a></td>
<td></td>
</tr>
<tr>
<td></td>
<td></td>
<td><a href="http://www.jetmore.org/john/code/swaks/" target="_blank" rel="noopener nofollow">swaks</a></td>
<td></td>
</tr>
<tr>
<td></td>
<td></td>
<td><a href="https://en.wikipedia.org/wiki/Sendmail" target="_blank" rel="noopener nofollow">sendmail</a></td>
<td></td>
</tr>
</tbody>
</table>