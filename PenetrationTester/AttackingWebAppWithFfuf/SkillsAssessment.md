# Skills Assessment - Web Fuzzing
You are given an online academy's IP address but have no further information about their website. As the first step of conducting a Penetration Test, you are expected to locate all pages and domains linked to their IP to enumerate the IP and domains properly.

Finally, you should do some fuzzing on pages you identify to see if any of them has any parameters that can be interacted with. If you do find active parameters, see if you can retrieve any data from them.

## Questions
1. Run a sub-domain/vhost fuzzing scan on '*.academy.htb' for the IP shown above. What are all the sub-domains you can identify? (Only write the sub-domain name) **Answer: test,archive,faculty**
   - Run a vhost fuzzing scan, filtering out HTTP responses with length equals to `985`:
        ```sh
        $ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://154.57.164.75:31090 -H 'Host: FUZZ.academy.htb' -fs 985

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://154.57.164.75:31090
        :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
        :: Header           : Host: FUZZ.academy.htb
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 985
        ________________________________________________

        test                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 158ms]
        archive                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 155ms]
        faculty                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 156ms]
        ```
2. Before you run your page fuzzing scan, you should first run an extension fuzzing scan. What are the different extensions accepted by the domains? **Answer: .php, .php7, .phps**
   - Create a list with the found subdomains, then run a fuzz on file extension for the default index page:
        ```sh
        $ cat subdomains.txt
        test
        archive
        faculty
        $ ffuf -w subdomains.txt:FUZZ1 -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ2 -u http://154.57.164.75:31090/indexFUZZ2 -H 'Host: FUZZ1.academy.htb' 

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://154.57.164.75:31090/indexFUZZ2
        :: Wordlist         : FUZZ1: /home/htb-ac-1863259/subdomains.txt
        :: Wordlist         : FUZZ2: /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt
        :: Header           : Host: FUZZ1.academy.htb
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        ________________________________________________

        [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 153ms]
            * FUZZ1: faculty
            * FUZZ2: .php

        [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 153ms]
            * FUZZ1: archive
            * FUZZ2: .php

        [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 155ms]
            * FUZZ1: test
            * FUZZ2: .php

        [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 152ms]
            * FUZZ1: faculty
            * FUZZ2: .php7

        [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 153ms]
            * FUZZ1: test
            * FUZZ2: .phps

        [Status: 403, Size: 284, Words: 20, Lines: 10, Duration: 153ms]
            * FUZZ1: faculty
            * FUZZ2: .phps

        [Status: 403, Size: 284, Words: 20, Lines: 10, Duration: 153ms]
            * FUZZ1: archive
            * FUZZ2: .phps
        ```
3. One of the pages you will identify should say 'You don't have access!'. What is the full page URL? **Answer: http://faculty.academy.htb:PORT/courses/linux-security.php7**
   - Add the found subdomain to /etc/hosts file:
        ```sh
        $ cat /etc/hosts
        <SNIP>
        154.57.164.81 test.academy.htb
        154.57.164.81 faculty.academy.htb
        154.57.164.81 archive.academy.htb
        <SNIP>
        ```
   - Run a for loop fuzzing recursively for pages with HTTP response length other than 287, 284, 0 and found the page:
        ```sh
        $ for sub in archive test faculty; do ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://$sub.academy.htb:32061/FUZZ -recursion -recursion-depth 1 -e .php,.phps,.php7 -v -t 200 -fs 287, 284, 0 -ic; done
        <SNIP>
        [Status: 200, Size: 774, Words: 223, Lines: 53, Duration: 154ms]
        | URL | http://faculty.academy.htb:32061/courses/linux-security.php7
            * FUZZ: linux-security.php7
        <SNIP>
        ```
4. In the page from the previous question, you should be able to find multiple parameters that are accepted by the page. What are they? **Answer: user, username**
   - Do both a GET-fuzzing and POST-fuzzing:
        ```sh
        $ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:32061/courses/linux-security.php7?FUZZ=key -fs 774

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://faculty.academy.htb:32061/courses/linux-security.php7?FUZZ=key
        :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 774
        ________________________________________________

        user                    [Status: 200, Size: 780, Words: 223, Lines: 53, Duration: 153ms]


        $ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:32061/courses/linux-security.php7 -X POST -d "FUZZ=key" -H "Content-Type: application/x-www-form-urlencoded" -fs 774

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : POST
        :: URL              : http://faculty.academy.htb:32061/courses/linux-security.php7
        :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
        :: Header           : Content-Type: application/x-www-form-urlencoded
        :: Data             : FUZZ=key
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 774
        ________________________________________________

        user                    [Status: 200, Size: 780, Words: 223, Lines: 53, Duration: 155ms]
        username                [Status: 200, Size: 781, Words: 223, Lines: 53, Duration: 156ms]
        ```
5. Try fuzzing the parameters you identified for working values. One of them should return a flag. What is the content of the flag? **Answer: HTB{w3b_fuzz1n6_m4573r}**
   - Notice that for key `username` the web responds with `User does not have access!`. Use this as the key and start fuzzing for usernames using this wordlist `/opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt`:
        ```sh
        $ ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ -u http://faculty.academy.htb:32061/courses/linux-security.php7 -X POST -d "username=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -fs 781

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : POST
        :: URL              : http://faculty.academy.htb:32061/courses/linux-security.php7
        :: Wordlist         : FUZZ: /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt
        :: Header           : Content-Type: application/x-www-form-urlencoded
        :: Data             : username=FUZZ
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 781
        ________________________________________________

        harry                   [Status: 200, Size: 773, Words: 218, Lines: 53, Duration: 154ms]
        ```
   - Use curl to read the response and get the flag:
        ```sh
        $ curl http://faculty.academy.htb:32061/courses/linux-security.php7 -X POST -d "username=harry" -H "Content-Type: application/x-www-form-urlencoded" 
        <SNIP>
        <div class='center'><p>HTB{w3b_fuzz1n6_m4573r}</p></div>
        <SNIP>
        ```