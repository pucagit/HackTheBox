# SMTP (port 25, 465, 587)
The Simple Mail Transfer Protocol (SMTP) is a protocol for sending emails in an IP network. 

SMTP works unencrypted without further measures and transmits all commands, data, or authentication information in plain text. To prevent unauthorized reading of data, the SMTP is used in conjunction with SSL/TLS encryption. Under certain circumstances, a server uses a port other than the standard TCP port 25 for the encrypted connection, for example, TCP port 465.

|Client||Submission Agent||Open Relay||Mail Delivery Agent||Mailbox|
|-|-|-|-|-|-|-|-|-|
|`MUA`|→|`MSA`|→|`MTA`|→|`MDA`|→|`POP3/IMAP`|
    
## Disadvantages
- Sending an email using SMTP does not return a usable delivery confirmation.
- Users are not authenticated when a connection is established, and the sender of an email is therefore unreliable, open SMTP relays are often misused to send spam en masse.

> For this purpose, an extension for SMTP has been developed called Extended SMTP (ESMTP). When people talk about SMTP in general, they usually mean ESMTP. ESMTP uses TLS, which is done after the EHLO command by sending STARTTLS. This initializes the SSL-protected SMTP connection, and from this moment on, the entire connection is encrypted, and therefore more or less secure. 

## Commands
To interact with the SMTP server, we can use the telnet tool to initialize a TCP connection with the SMTP server. The actual initialization of the session is done with the command mentioned above, HELO or EHLO. A list of all SMTP response codes can be found [here](https://serversmtp.com/smtp-error).
```
$ telnet <ip> 25
```
|Command|Description|
|-|-|
|`AUTH PLAIN`|AUTH is a service extension used to authenticate the client.|
|`HELO <mail_server>`|Start the session.|
|`MAIL FROM: <sender_email>`|Email sender.|
|`RCPT TO: <receiver_email>`|Email recipient.|
|`DATA`|Initiates the transmission of the email.|
|`RSET`|Aborts the initiated transmission but keeps the connection between client and server.|
|`VRFY <user>`|Checks if a mailbox is available for message transfer.|
|`EXPN`|Checks if a mailbox is available for messaging with this command.|
|`NOOP`|Requests a response from the server to prevent disconnection due to time-out.|
|`QUIT`|Terminates the session.|

To prevent the sent emails from being filtered by spam filters and not reaching the recipient, the sender can use a relay server that the recipient trusts. It is an SMTP server that is known and verified by all others. As a rule, the sender must authenticate himself to the relay server before using it.

## Dangerous Settings
Open Relay Configuration: `mynetwork = 0.0.0.0/0`. With this setting, this SMTP server can send fake emails and thus initialize communication between multiple parties. Another attack possibility would be to spoof the email and read it.

## Questions
1. Enumerate the SMTP service and submit the banner, including its version as the answer. **Answer: InFreight ESMTP v2.11**
   - `$ sudo nmap -sV -sC -p25 <ip>`
2. Enumerate the SMTP service even further and find the username that exists on the system. Submit it as the answer. **Answer: robin**
   - Increase the timeout to 20s: `$ smtp-user-enum -v -M RCPT -m 10 -U footprinting-wordlist.txt -w 20 -t 10.129.24.197`