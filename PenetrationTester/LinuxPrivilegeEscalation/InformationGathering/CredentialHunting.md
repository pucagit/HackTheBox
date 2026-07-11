# Credential Hunting
The `/var` directory typically contains the web root for whatever web server is running on the host. The web root may contain database credentials or other types of credentials that can be leveraged to further access. A common example is MySQL database credentials within WordPress configuration files:

```shellsession
$ grep 'DB_USER\|DB_PASSWORD' wp-config.php
```

The spool or mail directories, if accessible, may also contain valuable information or even credentials. It is common to find credentials stored in files in the web root 

```shellsession
$  find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

## SSH Keys
We may locate a private key for another, more privileged, user that we can use to connect back to the box with additional privileges. We may also sometimes find SSH keys that can be used to access other hosts in the environment. Whenever finding SSH keys check the `known_hosts` file to find targets. This file contains a list of public keys for all the hosts which the user has connected to in the past and may be useful for lateral movement or to find data on a remote host that can be used to perform privilege escalation on our target.

```shellsession
$  ls ~/.ssh

id_rsa  id_rsa.pub  known_hosts
```

## Questions
SSH to with user `htb-student` and password `Academy_LLPE!`
1. Find the WordPress database password. **Answer: W0rdpr3ss_sekur1ty!**
   - Locate the Wordpress database password and grep for it:
        ```shellsession
        $ find / -name "wp-config*" -type f 2>/dev/null
        /var/www/html/wp-config.php
        /var/www/html/wp-config-sample.php
        htb-student@NIX02:~$ grep 'DB_USER\|DB_PASSWORD' /var/www/html/wp-config.php
        define( 'DB_USER', 'wordpressuser' );
        define( 'DB_PASSWORD', 'W0rdpr3ss_sekur1ty!' );
        ```