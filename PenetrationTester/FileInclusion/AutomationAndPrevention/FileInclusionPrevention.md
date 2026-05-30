# File Inclusion Prevention
## Questions 
SSH to with user "htb-student" and password "HTB_@cademy_stdnt!"
1. What is the full path to the php.ini file for Apache? **Answer: /etc/php/7.4/apache2/php.ini**
   - SSH to the machine and look for that file:
        ```sh
        $ find / -name "*php.ini"
        <SNIP>
        /etc/php/7.4/apache2/php.ini
        <SNIP>
        ```
2. Edit the php.ini file to block system(), then try to execute PHP Code that uses system. Read the /var/log/apache2/error.log file and fill in the blank: system() has been disabled for ________ reasons. **Answer:**