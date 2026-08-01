# GET
## HTTP Basic Auth
Unlike the usual login forms, which utilize HTTP parameters to validate the user credentials (e.g. POST request), this type of authentication utilizes a `basic HTTP authentication`, which is handled directly by the webserver to protect a specific page/directory, without directly interacting with the web application.

```shellsession
$ curl -u admin:admin http://<SERVER_IP>:<PORT>/
$ curl http://admin:admin@<SERVER_IP>:<PORT>/
```

## HTTP Authorization Header
As we are using `basic HTTP auth`, we see that our HTTP request sets the `Authorization` header to `Basic YWRtaW46YWRtaW4=`, which is the base64 encoded value of `admin:admin.` If we were using a modern method of authentication (e.g. `JWT`), the `Authorization` would be of type `Bearer` and would contain a longer encrypted token.

## Questions
Authenticate to 154.57.164.74 , with user `admin` and password `admin`
1. The exercise above seems to be broken, as it returns incorrect results. Use the browser devtools to see what is the request it is sending when we search, and use cURL to search for 'flag' and obtain the flag. **Answer: HTB{curl_g3773r}**
   - Use this curl command:
        ```shellsession
        $ curl 'http://154.57.164.74:32170/search.php?search=flag' -H 'Authorization: Basic YWRtaW46YWRtaW4=' -i
        HTTP/1.1 200 OK
        Date: Sat, 01 Aug 2026 16:40:42 GMT
        Server: Apache/2.4.41 (Ubuntu)
        Cache-Control: no-cache, must-revalidate, max-age=0
        Content-Length: 23
        Content-Type: text/html; charset=UTF-8

        flag: HTB{curl_g3773r}
        ```