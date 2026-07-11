# File Inclusion Prevention
## Questions 
SSH to with user "htb-student" and password "HTB_@cademy_stdnt!"
1. What is the full path to the php.ini file for Apache? **Answer: /etc/php/7.4/apache2/php.ini**
   - SSH to the machine and look for that file:
        ```shellsession
        $ find / -name "*php.ini"
        <SNIP>
        /etc/php/7.4/apache2/php.ini
        <SNIP>
        ```
2. Edit the php.ini file to block system(), then try to execute PHP Code that uses system. Read the /var/log/apache2/error.log file and fill in the blank: system() has been disabled for ________ reasons. **Answer: security**
   - Locate the `php.ini` file:\
        ```shellsession
        $ php --ini
        Configuration File (php.ini) Path: /etc/php/7.4/cli
        Loaded Configuration File:         /etc/php/7.4/cli/php.ini
        <SNIP>
        ```
   - Add system to `disable_functions` in `/etc/php/7.4/cli/php.ini` (use `Ctrl`+`W` to find it):
        ```
        disable_functions = system      
        ```
   - Test the system() command and read the error log:
        ```
        $ cat test.php
        <?php echo system('echo "The system function is STILL active!"');?>
        $ php test.php
        PHP Warning:  system() has been disabled for security reasons in /var/www/html/test.php on line 2
        ```