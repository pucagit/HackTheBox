# Linux Authentication Process
Linux-based distributions support various authentication mechanisms. One of the most commonly used is [Pluggable Authentication Modules (PAM)](https://web.archive.org/web/20220622215926/http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html). The modules responsible for this functionality, such as `pam_unix.so` or `pam_unix2.so`, are typically located in `/usr/lib/x86_64-linux-gnu/security/` on Debian-based systems. These modules manage user information, authentication, sessions, and password changes. 

## Passwd file
The `/etc/passwd` file contains information about every user on the system and is readable by all users and services. Each entry in the file corresponds to a single user and consists of 7 fields, which store user-related data in a structured format. 

```
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

<table class="table table-striped text-left">
<thead>
<tr>
<th>Field</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr>
<td>Username</td>
<td><code>htb-student</code></td>
</tr>
<tr>
<td>Password</td>
<td><code>x</code></td>
</tr>
<tr>
<td>User ID</td>
<td><code>1000</code></td>
</tr>
<tr>
<td>Group ID</td>
<td><code>1000</code></td>
</tr>
<tr>
<td><a href="https://en.wikipedia.org/wiki/Gecos_field" target="_blank" rel="noopener nofollow">GECOS</a></td>
<td><code>,,,</code></td>
</tr>
<tr>
<td>Home directory</td>
<td><code>/home/htb-student</code></td>
</tr>
<tr>
<td>Default shell</td>
<td><code>/bin/bash</code></td>
</tr>
</tbody>
</table>

The most relevant field for our purposes is the **Password** field, as it can contain different types of entries. In rare cases (generally on very old systems) this field may hold the actual password hash. On modern systems, however, password hashes are stored in the `/etc/shadow` file, which we'll examine later. Despite this, the `/etc/passwd` file is world-readable, giving attackers the ability to crack the passwords if hashes are stored here.

Usually, we will find the value `x` in this field, indicating that the passwords are stored in a hashed form within the `/etc/shadow` file. However, it can also be that the `/etc/passwd` file is writeable by mistake. This would allow us to remove the password field for the root user entirely. This results in no password prompt being displayed when attempting to log in as `root`.

## Shadow file
It has a similar format to `/etc/passwd` but is solely responsible for password storage and management. It contains all password information for created users. The `/etc/shadow` file is also only readable by users with administrative privileges. The format of this file is divided into the following 9 fields:

```
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

<table class="table table-striped text-left">
<thead>
<tr>
<th>Field</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr>
<td>Username</td>
<td><code>htb-student</code></td>
</tr>
<tr>
<td>Password</td>
<td><code>$y$j9T$3QSBB6CbHEu...SNIP...f8Ms</code></td>
</tr>
<tr>
<td>Last change</td>
<td><code>18955</code></td>
</tr>
<tr>
<td>Min age</td>
<td><code>0</code></td>
</tr>
<tr>
<td>Max age</td>
<td><code>99999</code></td>
</tr>
<tr>
<td>Warning period</td>
<td><code>7</code></td>
</tr>
<tr>
<td>Inactivity period</td>
<td><code>-</code></td>
</tr>
<tr>
<td>Expiration date</td>
<td><code>-</code></td>
</tr>
<tr>
<td>Reserved field</td>
<td><code>-</code></td>
</tr>
</tbody>
</table>

If the **Password** field contains a character such as `!` or `*`, the user cannot log in using a Unix password. However, other authentication methods—such as Kerberos or key-based authentication—can still be used. The same applies if the **Password** field is empty, meaning no password is required for login. This can lead to certain programs denying access to specific functions. The **Password** field also follows a particular format, from which we can extract additional information:

```
$<id>$<salt>$<hashed>
```

As we can see here, the hashed passwords are divided into three parts. The **ID** value specifies which cryptographic hash algorithm was used, typically one of the following:

<table class="table table-striped text-left">
<thead>
<tr>
<th>ID</th>
<th>Cryptographic Hash Algorithm</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>1</code></td>
<td><a href="https://en.wikipedia.org/wiki/MD5" target="_blank" rel="noopener nofollow">MD5</a></td>
</tr>
<tr>
<td><code>2a</code></td>
<td><a href="https://en.wikipedia.org/wiki/Blowfish_(cipher)" target="_blank" rel="noopener nofollow">Blowfish</a></td>
</tr>
<tr>
<td><code>5</code></td>
<td><a href="https://en.wikipedia.org/wiki/SHA-2" target="_blank" rel="noopener nofollow">SHA-256</a></td>
</tr>
<tr>
<td><code>6</code></td>
<td><a href="https://en.wikipedia.org/wiki/SHA-2" target="_blank" rel="noopener nofollow">SHA-512</a></td>
</tr>
<tr>
<td><code>sha1</code></td>
<td><a href="https://en.wikipedia.org/wiki/SHA-1" target="_blank" rel="noopener nofollow">SHA1crypt</a></td>
</tr>
<tr>
<td><code>y</code></td>
<td><a href="https://github.com/openwall/yescrypt" target="_blank" rel="noopener nofollow">Yescrypt</a></td>
</tr>
<tr>
<td><code>gy</code></td>
<td><a href="https://www.openwall.com/lists/yescrypt/2019/06/30/1" target="_blank" rel="noopener nofollow">Gost-yescrypt</a></td>
</tr>
<tr>
<td><code>7</code></td>
<td><a href="https://en.wikipedia.org/wiki/Scrypt" target="_blank" rel="noopener nofollow">Scrypt</a></td>
</tr>
</tbody>
</table>

## Opasswd
The PAM library (`pam_unix.so`) can prevent users from reusing old passwords. These previous passwords are stored in the `/etc/security/opasswd` file. Administrator (root) privileges are required to read this file, assuming its permissions have not been modified manually.

```sh
masterofblafu@htb[/htb]$ sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

This file uses MD5 to hash the password, which is significantly easier to crack than SHA-512.

## Cracking Linux Credentials
Once we have root access on a Linux machine, we can gather user password hashes and attempt to crack them using various methods to recover the plaintext passwords. To do this, we can use a tool called [unshadow](https://github.com/pmittaldev/john-the-ripper/blob/master/src/unshadow.c), which is included with John the Ripper (JtR). It works by combining the `passwd` and `shadow` files into a single file suitable for cracking.

```sh
masterofblafu@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak 
masterofblafu@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak 
masterofblafu@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

This "unshadowed" file can now be attacked with either JtR or hashcat.

```sh
masterofblafu@htb[/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

## Questions
1. Download the attached ZIP file (linux-authentication-process.zip), and use single crack mode to find martin's password. What is it? **Answer: Martin1**
   - Combine the 2 file to unshadow it and crack the password:
        ```sh
        $ cp passwd /tmp/passwd.bak
        $ cp shadow /tmp/shadow.bak
        $ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
        $ cat /tmp/unshadowed.cracked 
        $6$EBOM5vJAV1TPvrdP$LqsLyYkoGzAGt4ihyvfhvBrrGpVjV976B3dEubi9i95P5cDx1U6BrE9G020PWuaeI6JSNaIDIbn43uskRDG0U/:mariposa
        $6$0XiU8Oe/pGpxWvdq$n6TgiYUVAXBUOO11C155Ea8nNpSVtFFVQveY6yExlOdPu99hY4V9Chi1KEy/lAluVFuVcvi8QCO1mCG6ra70A1:Martin1
        ```
2. Use a wordlist attack to find sarah's password. What is it? **Answer: mariposa**
   - Already cracked from the above hashcat run.