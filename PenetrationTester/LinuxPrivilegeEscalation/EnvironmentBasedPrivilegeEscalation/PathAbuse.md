# Path Abuse
PATH is an environment variable that specifies the set of directories where an executable can be located.

```shellsession
$ echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

If we can modify a user's path, we could replace a common binary such as `ls` with a malicious script such as a reverse shell. If we add `.` to the path by issuing the command `PATH=.:$PATH` and then `export PATH`, we will be able to run binaries located in our current working directory by just typing the name of the file:

```shellsession
$ PATH=.:${PATH}
$ export PATH
$ echo $PATH

.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
$ touch ls
$ echo 'echo "PATH ABUSE!!"' > ls
$ chmod +x ls
$ ls

PATH ABUSE!!
```

## Questions
SSH to 10.129.41.129 (ACADEMY-LPE-NIX02), with user "htb-student" and password "Academy_LLPE!"
1. Review the PATH of the htb-student user. What non-default directory is part of the user's PATH? **Answer: /tmp**
   - Review the PATH environment variable:
        ```shellsession
        $ echo $PATH
        /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/tmp
        ```