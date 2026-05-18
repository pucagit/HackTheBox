# Directory Fuzzing
We can assign a wordlist to a keyword to refer to it where we want to fuzz:

```sh
masterofblafu@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

<SNIP>
blog                    [Status: 301, Size: 326, Words: 20, Lines: 10]
:: Progress: [87651/87651] :: Job [1/1] :: 9739 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

We can even make it go faster with `-t 200`.

## Questions
1. In addition to the directory we found above, there is another directory that can be found. What is it? **Answer: forum**
   - Add `-ic` flag to ignore comment lines:
        ```sh
        $ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://154.57.164.74:31960/FUZZ -ic

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://154.57.164.74:31960/FUZZ
        :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        ________________________________________________

        blog                    [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 154ms]
                                [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 156ms]
        forum                   [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 153ms]
        ```