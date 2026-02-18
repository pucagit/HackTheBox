# IMAP/POP3 (port 143,993/110,995)
With the help of the Internet Message Access Protocol (IMAP), access to emails from a mail server is possible. Unlike the Post Office Protocol (POP3), IMAP allows online management of emails directly on the server and supports folder structures. Thus, it is a network protocol for the online management of emails on a remote server. The protocol is client-server-based and allows synchronization of a local email client with the mailbox on the server, providing a kind of network file system for emails, allowing problem-free synchronization across several independent clients. POP3, on the other hand, does not have the same functionality as IMAP, and it only provides listing, retrieving, and deleting emails as functions at the email server.

Without further measures, IMAP works unencrypted and transmits commands, emails, or usernames and passwords in plain text. Many email servers require establishing an encrypted IMAP session to ensure greater security in email traffic and prevent unauthorized access to mailboxes. SSL/TLS is usually used for this purpose. Depending on the method and implementation used, the encrypted connection uses the standard port 143 or an alternative port such as 993.

## Default Configuration
### IMAP Commands
|Command|Description|
|-|-|
|`1 LOGIN username password`|User's login.|
|`1 LIST "" *`|Lists all directories.|
|`1 CREATE "INBOX"`|Creates a mailbox with the specified name.|
|`1 DELETE "INBOX"`|Deletes a mailbox.|
|`1 RENAME "ToRead" "Important"`|Renames a mailbox.|
|`1 LSUB "" *`|Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`.|
|`1 SELECT INBOX`|Selects a mailbox so that messages in the mailbox can be accessed.|
|`1 UNSELECT INBOX`|Exits the selected mailbox.|
|`1 FETCH <id> all`|Retrieves metadata associated with a message in the mailbox.|
|`1 FETCH <id> BODY[TEXT]`|Retrieves message's body in the mailbox.|
|`1 CLOSE`|Removes all messages with the `Deleted` flag set.|
|`1 LOGOUT`|Closes the connection with the IMAP server.|

### POP3 Commands
|Command|Description|
|-|-|
|`USER username`|Identifies the user.|
|`PASS password`|Authentication of the user using its password..|
|`STAT`|Requests the number of saved emails from the server.|
|`LIST`|Requests from the server the number and size of all emails.|
|`RETR id`|Requests the server to deliver the requested email by ID.|
|`DELE id`|	Requests the server to delete the requested email by ID.|
|`CAPA`|Requests the server to display the server capabilities.|
|`RSET`|Requests the server to reset the transmitted information.|
|`QUIT`|Closes the connection with the POP3 server.|

## Dangerous Settings
|Setting|Description|
|-|-|
|`auth_debug`|Enables all authentication debug logging.|
|`auth_debug_passwords`|This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.|
|`auth_verbose`|Logs unsuccessful authentication attempts and their reasons.|
|`auth_verbose_passwords`|Passwords used for authentication are logged and can also be truncated.|
|`auth_anonymous_username`|This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism.|

## Interacting
### cURL
```
$ curl -k 'imaps://<ip>' --user <username>:<password> -v
```
### OpenSSL
```
$ openssl s_client -connect <ip>:pop3s
$ openssl s_client -connect <ip>:imaps
```

## Questions
1. Figure out the exact organization name from the IMAP/POP3 service and submit it as the answer. **Answer: InlaneFreight Ltd**
   - `$ sudo nmap -sV -sC -p143,110,993,995 <ip>`
2. What is the FQDN that the IMAP and POP3 servers are assigned to? **Answer: dev.inlanefreight.htb**
   - `$ sudo nmap -sV -sC -p143,110,993,995 <ip>`
3. Enumerate the IMAP service and submit the flag as the answer. (Format: HTB{...}) **Answer: HTB{roncfbw7iszerd7shni7jr2343zhrj}**
   - `$ openssl s_client -connect <ip>:imaps` -> Read the first OK response
4. What is the customized version of the POP3 server? **Answer: InFreight POP3 v9.188**
   - `$ openssl s_client -connect <ip>:pop3s` -> Read the first OK response
5. What is the admin email address? **Answer: devadmin@inlanefreight.htb**
   - `$ openssl s_client -connect <ip>:imaps`
   - `1 LIST "" *` -> found DEV.DEPARTMENT.INT directory
   - `1 SELECT DEV.DEPARTMENT.INT` -> `1 FETCH 1 all` -> read the metadata inside `ENVELOPE`
6. Try to access the emails on the IMAP server and submit the flag as the answer. (Format: HTB{...}) **Answer: HTB{983uzn8jmfgpd8jmof8c34n7zio}**
   - `$ openssl s_client -connect <ip>:imaps`
   - `1 LIST "" *` -> found DEV.DEPARTMENT.INT directory
   - `1 SELECT DEV.DEPARTMENT.INT` -> `1 FETCH 1 BODY[TEXT]` -> read the email's body to get the flag