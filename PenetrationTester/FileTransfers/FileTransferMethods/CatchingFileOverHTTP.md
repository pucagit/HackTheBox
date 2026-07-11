# Catching Files over HTTP/S
## Nginx - Enabling PUT
### Create a Directory to Handle Uploaded Files

```shellsession
masterofblafu@htb[/htb]$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```

### Change the Owner to www-data

```shellsession
masterofblafu@htb[/htb]$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

### Create Nginx Configuration File
Create the Nginx configuration file by creating the file `/etc/nginx/sites-available/upload.conf` with the contents:

```shellsession
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

### Symlink our Site to the sites-enabled Directory

```shellsession
masterofblafu@htb[/htb]$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

### Start Nginx

```shellsession
masterofblafu@htb[/htb]$ sudo systemctl restart nginx.service
```

### Verifying Errors

```shellsession
masterofblafu@htb[/htb]$ tail -2 /var/log/nginx/error.log

2020/11/17 16:11:56 [emerg] 5679#5679: bind() to 0.0.0.0:`80` failed (98: A`ddress already in use`)
2020/11/17 16:11:56 [emerg] 5679#5679: still could not bind()
```

```shellsession
masterofblafu@htb[/htb]$ ss -lnpt | grep 80

LISTEN 0      100          0.0.0.0:80        0.0.0.0:*    users:(("python",pid=`2811`,fd=3),("python",pid=2070,fd=3),("python",pid=1968,fd=3),("python",pid=1856,fd=3))
```

```shellsession
masterofblafu@htb[/htb]$ ps -ef | grep 2811

user65      2811    1856  0 16:05 ?        00:00:04 `python -m websockify 80 localhost:5901 -D`
root        6720    2226  0 16:14 pts/0    00:00:00 grep --color=auto 2811
```

### Remove NginxDefault Configuration

```shellsession
masterofblafu@htb[/htb]$ sudo rm /etc/nginx/sites-enabled/default
```

### Upload File Using cURL

```shellsession
masterofblafu@htb[/htb]$ curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```

```shellsession
masterofblafu@htb[/htb]$ sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt 

user65:x:1000:1000:,,,:/home/user65:/bin/bash
```