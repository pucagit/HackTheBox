# Parameter Fuzzing - GET

```sh
masterofblafu@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

<...SNIP...>                    [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

> Once again, we will get many results back, so we will filter out the default response size we are getting.

## Questions
1. Using what you learned in this section, run a parameter fuzzing scan on this page. What is the parameter accepted by this webpage? **Answer: user**
   - First start a scouting scan for the common HTTP response size → `798`:
        ```sh
        $ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:30274/admin/admin.php?FUZZ=key 
        <SNIP>
        addrule                 [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 153ms]
        addsite                 [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 153ms]
        addtag                  [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 153ms]
        addtxt                  [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 153ms]
        addurl                  [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 153ms]
        addtype                 [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 154ms]
        adduser                 [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 153ms]
        addusers                [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 153ms]
        adlr                    [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 154ms]
        adm                     [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 154ms]
        admid                   [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 153ms]
        adminEmail              [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 153ms]
        admin                   [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 154ms]
        adminEnableRecovery     [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 155ms]
        adminPWD                [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 155ms]
        adminPass               [Status: 200, Size: 798, Words: 227, Lines: 54, Duration: 155ms]
        <SNIP>
        ```
   - This time filter out HTTP responses with size equals to `798`:
        ```sh
        $ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:30274/admin/admin.php?FUZZ=key -fs 798

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://admin.academy.htb:30274/admin/admin.php?FUZZ=key
        :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 798
        ________________________________________________

        user                    [Status: 200, Size: 783, Words: 221, Lines: 54, Duration: 153ms]
        ```