# Filtering Results
Filter HTTP responses with size equal to 900 using option `-fs 900`:

```sh
masterofblafu@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs 900


       /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://academy.htb:PORT/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.academy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 900
________________________________________________

<...SNIP...>
admin                   [Status: 200, Size: 0, Words: 1, Lines: 1]
:: Progress: [4997/4997] :: Job [1/1] :: 1249 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

## Questions
1. Try running a VHost fuzzing scan on 'academy.htb', and see what other VHosts you get. What other VHosts did you get? **Answer: test.academy.htb**
   - First run a default fuzzing to identify what the default HTTP response size is → `986`:
        ```sh
        $ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://154.57.164.80:30973 -H 'Host: FUZZ.academy.htb'
        <SNIP>
        mk                      [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 160ms]
        bw                      [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 153ms]
        em                      [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        creative                [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 153ms]
        www.elearning           [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 153ms]
        ad2                     [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        stars                   [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        friend                  [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 153ms]
        discovery               [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        buffalo                 [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 153ms]
        reservations            [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        cdp                     [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 153ms]
        uxs2r                   [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 153ms]
        cosmos                  [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        www.business            [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 153ms]
        atom                    [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 155ms]
        a2                      [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        xcb                     [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        allegro                 [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        ufa                     [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        om                      [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 156ms]
        dw                      [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 154ms]
        <SNIP>
        ```
   - Run a second fuzz filtering this HTTP response size out:
        ```sh
        $ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://154.57.164.80:30973 -H 'Host: FUZZ.academy.htb' -fs 986

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://154.57.164.80:30973
        :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
        :: Header           : Host: FUZZ.academy.htb
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 986
        ________________________________________________

        admin                   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 154ms]
        test                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 155ms]
        ```