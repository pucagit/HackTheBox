# Value Fuzzing
## Custom Wordlist
When it comes to fuzzing parameter values, we may not always find a pre-made wordlist that would work for us, as each parameter would expect a certain type of value.

Example of creating a list of numeric IDs:

```sh
$ for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

## Value Fuzzing

```sh
masterofblafu@htb[/htb]$ ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.academy.htb:30794/admin/admin.php
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : id=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

<...SNIP...>                      [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

## Questions
1. Try to create the 'ids.txt' wordlist, identify the accepted value with a fuzzing scan, and then use it in a 'POST' request with 'curl' to collect the flag. What is the content of the flag? **Answer: p4r4m373r_fuzz1n6_15_k3y!**
   - Add `admin.academy.htb` to `/etc/hosts` file
   - Start by fuzzing for the parameter key → `id`:
        ```sh
        $ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:30274/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 798

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : POST
        :: URL              : http://admin.academy.htb:30274/admin/admin.php
        :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
        :: Header           : Content-Type: application/x-www-form-urlencoded
        :: Data             : FUZZ=key
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 798
        ________________________________________________

        id                      [Status: 200, Size: 768, Words: 219, Lines: 54, Duration: 153ms]
        ```
   - Create a fuzzing list (`ids.txt`) with ids ranging from 0..1000 then use this list to fuzz for the right id:
        ```sh
        $ for i in $(seq 1 1000); do echo $i >> ids.txt; done
        $ ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:30274/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 768

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : POST
        :: URL              : http://admin.academy.htb:30274/admin/admin.php
        :: Wordlist         : FUZZ: /home/htb-ac-1863259/ids.txt
        :: Header           : Content-Type: application/x-www-form-urlencoded
        :: Data             : id=FUZZ
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        :: Filter           : Response size: 768
        ________________________________________________

        73                      [Status: 200, Size: 787, Words: 218, Lines: 54, Duration: 153ms]
        ```
    - Use `curl` to read the flag:
        ```s
        $ curl http://admin.academy.htb:30274/admin/admin.php -X POST -d 'id=73'
        <div class='center'><p>HTB{p4r4m373r_fuzz1n6_15_k3y!}</p></div>
        <SNIP>
        ```