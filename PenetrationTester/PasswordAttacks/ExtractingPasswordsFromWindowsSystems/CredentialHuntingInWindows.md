# Credential Hunting in Windows
**Credential hunting** is the process of performing detailed searches across the file system and through various applications to discover credentials. To understand this concept, let's place ourselves in a scenario. We have gained access to an IT admin's Windows 10 workstation through RDP.

## Search-centric 
### Key terms to search for
Whether we end up with access to the GUI or CLI, we know we will have some tools to use for searching but of equal importance is what exactly we are searching for. Here are some helpful key terms we can use that can help us discover some credentials:

- Passwords
- Passphrases
- Keys
- Username
- User account
- Creds
- Users
- Passkeys
- configuration
- dbcredential
- dbpassword
- pwd
- Login
- Credentials

## Search Tools
### Windows Search
With access to the GUI, it is worth attempting to use **Windows Search** to find files on the target using some of the keywords mentioned above. By default, it will search various OS settings and the file system for files and applications containing the key term entered in the search bar.

### LaZagne
We can also take advantage of third-party tools like [LaZagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store. 
<table class="table table-striped text-left">
<thead>
<tr>
<th>Module</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>browsers</td>
<td>Extracts passwords from various browsers including Chromium, Firefox, Microsoft Edge, and Opera</td>
</tr>
<tr>
<td>chats</td>
<td>Extracts passwords from various chat applications including Skype</td>
</tr>
<tr>
<td>mails</td>
<td>Searches through mailboxes for passwords including Outlook and Thunderbird</td>
</tr>
<tr>
<td>memory</td>
<td>Dumps passwords from memory, targeting KeePass and LSASS</td>
</tr>
<tr>
<td>sysadmin</td>
<td>Extracts passwords from the configuration files of various sysadmin tools like OpenVPN and WinSCP</td>
</tr>
<tr>
<td>windows</td>
<td>Extracts Windows-specific credentials targeting LSA secrets, Credential Manager, and more</td>
</tr>
<tr>
<td>wifi</td>
<td>Dumps WiFi credentials</td>
</tr>
</tbody>
</table>

> **Note:** Web browsers are some of the most interesting places to search for credentials, due to the fact that many of them offer built-in credential storage. In the most popular browsers, such as **Google Chrome**, **Microsoft Edge**, and **Firefox**, stored credentials are encrypted. However, many tools for decrypting the various credentials databases used can be found online, such as [firefox_decrypt](https://github.com/unode/firefox_decrypt) and [decrypt-chrome-passwords](https://github.com/ohyicong/decrypt-chrome-passwords). LaZagne supports **35** different browsers on Windows.

It would be beneficial to keep a [standalone copy](https://github.com/AlessandroZ/LaZagne/releases/) of LaZagne on our attack host so we can quickly transfer it over to the target. Once `LaZagne.exe` is on the target, we can execute LaZagne and run `all` included modules:

```cmd
C:\Users\bob\Desktop> start LaZagne.exe all
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22
```

### findstr
```cmd
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Additional Considerations
Here are some other places we should keep in mind when credential hunting:

- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- Password in unattend.xml
- Passwords in the AD user or computer description fields
- KeePass databases (if we are able to guess or crack the master password)
- Found on user systems and shares
- Files with names like pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, and Sharepoint

## Questions
You have gained access to an IT admin's Windows 10 workstation and begin your credential hunting process by searching for credentials in common storage locations. RDP to **10.129.8.61** (ACADEMY-PWATTACKS-WIN10CHUNTING) with user `Bob` and password `HTB_@cademy_stdnt!`

1. What password does Bob use to connect to the Switches via SSH? (Format: Case-Sensitive) **Answer: WellConnected123**
   - Find in `C:\Users\Bob\Desktop\WorkStuff\Creds\passwords`
2. What is the GitLab access code Bob uses? (Format: Case-Sensitive) **Answer: 3z1ePfGbjWPsTfCsZfjy**
   - Find in `C:\Users\Bob\DesktopWorkStuff\Creds\GitlabAccessCodeJustIncase`
3. What credentials does Bob use with WinSCP to connect to the file server? (Format: username:password, Case-Sensitive) **Answer: ubuntu:FSadmin123**
   - Download [LaZagne](https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.7/LaZagne.exe) on attack host
   - Transfer the `LaZagne.exe` to the target machine using `python -m http.server`
   - On the target run the executable and observe the credentials: `C:\Users\Bob\Downloads>start LaZagne.exe all`
4. What is the default password of every newly created Inlanefreight Domain user account? (Format: Case-Sensitive) **Answer: Inlanefreightisgreat2022**
   - Find in `C:\Automations&Scripts\BulkaddADusers`
5. What are the credentials to access the Edge-Router? (Format: username:password, Case-Sensitive) **Answer: edgeadmin:Edge@dmin123!**
   - Find in `C:\Automations&Scripts\AnsibleScripts\EdgeRouterConfigs`