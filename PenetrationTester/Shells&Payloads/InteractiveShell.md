# Spawning Interactive Shells
## /bin/sh -i
This command will execute the shell interpreter specified in the path in interactive mode (`-i`).
```
/bin/sh -i
sh: no job control in this shell
sh-4.2$
```
## Perl
If the programming language Perl is present on the system, these commands will execute the shell interpreter specified.
```
perl —e 'exec "/bin/sh";'
```
```
perl: exec "/bin/sh";
```
The command directly above should be run from a script.
## Ruby
If the programming language Ruby is present on the system, this command will execute the shell interpreter specified:
```
ruby: exec "/bin/sh"
```
The command directly above should be run from a script.
## Lua 
If the programming language Lua is present on the system, we can use the `os.execute` method to execute the shell interpreter specified using the full command below:
```
lua: os.execute('/bin/sh')
```
The command directly above should be run from a script.
## AWK
AWK is a C-like pattern scanning and processing language present on most UNIX/Linux-based systems, widely used by developers and sysadmins to generate reports. It can also be used to spawn an interactive shell. This is shown in the short awk script below:
```
awk 'BEGIN {system("/bin/sh")}'
```
## Find
Find is a command present on most Unix/Linux systems widely used to search for & through files and directories using various criteria. It can also be used to execute applications and invoke a shell interpreter.
```
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```
```
find . -exec /bin/sh \; -quit
```
## VIM
```
vim -c ':!/bin/sh'
```
```
vim
:set shell=/bin/sh
:shell
```
## Execution Permissions Considerations
**Permissions**
```
ls -la <path/to/fileorbinary>
```
**Sudo -l**
```
sudo -l
Matching Defaults entries for apache on ILF-WebSrv:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```