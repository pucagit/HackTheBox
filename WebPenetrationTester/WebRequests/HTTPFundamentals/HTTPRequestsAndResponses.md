# HTTP Requests and Responses
## Questions
1. What is the HTTP method used while intercepting the request? (case-sensitive) **Answer: GET**
2. Send a GET request to the above server, and read the response headers to find the version of Apache running on the server, then submit it as the answer. (answer format: X.Y.ZZ) **Answer: 2.4.41**
   - Use curl to read the response headers:
        ```shellsession
        $ curl -I http://154.57.164.76:30306
        HTTP/1.1 200 OK
        Date: Sat, 01 Aug 2026 16:25:38 GMT
        Server: Apache/2.4.41 (Ubuntu)
        Content-Type: text/html; charset=UTF-8
        ```