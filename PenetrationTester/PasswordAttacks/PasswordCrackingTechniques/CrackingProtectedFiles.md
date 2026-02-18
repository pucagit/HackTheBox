# Cracking Protected Files
In many cases, **symmetric encryption** algorithms such as AES-256 are used to securely **store individual files or folders**. In this method, the same key is used for both encryption and decryption. For **transmitting files**, **asymmetric encryption** is typically employed, which uses two distinct keys: the sender encrypts the file with the recipient's public key, and the recipient decrypts it using the corresponding private key.

## Hunting for Encrypted Files
Many different extensions correspond to encrypted files—a useful reference list can be found on [FileInfo](https://fileinfo.com/filetypes/encoded). As an example, consider this command we might use to locate commonly encrypted files on a Linux system:
```
$ for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

File extension:  .xls

File extension:  .xls*

File extension:  .xltx

File extension:  .od*
/home/cry0l1t3/Docs/document-temp.odt
/home/cry0l1t3/Docs/product-improvements.odp
/home/cry0l1t3/Docs/mgmt-spreadsheet.ods
...SNIP...
```

## Hunting for SSH keys
SSH private keys always begin with `-----BEGIN [...SNIP...] PRIVATE KEY-----`. We can use tools like `grep` to recursively search the file system for them during post-exploitation.
```
$ grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null

/home/jsmith/.ssh/id_ed25519:1:-----BEGIN OPENSSH PRIVATE KEY-----
/home/jsmith/.ssh/SSH.private:1:-----BEGIN RSA PRIVATE KEY-----
/home/jsmith/Documents/id_rsa:1:-----BEGIN OPENSSH PRIVATE KEY-----
<SNIP>
```
One way to tell whether an SSH key is encrypted or not, is to try reading the key with `ssh-keygen`.
```
$ ssh-keygen -yf ~/.ssh/id_ed25519 

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpNefJd834VkD5iq+22Zh59Gzmmtzo6rAffCx2UtaS6
```
## Cracking encrypted SSH keys
JtR has many different scripts for extracting hashes from files—which we can then proceed to crack. We can find these scripts on our system using the following command:
```
$ locate *2john*

/usr/bin/bitlocker2john
/usr/bin/dmg2john
/usr/bin/gpg2john
/usr/bin/hccap2john
/usr/bin/keepass2john
/usr/bin/putty2john
<SNIP>
```
For example, we could use the Python script `ssh2john.py` to acquire the corresponding hash for an encrypted SSH key, and then use JtR to try and crack it.
```
$ ssh2john.py SSH.private > ssh.hash
$ john --wordlist=rockyou.txt ssh.hash
$ john ssh.hash --show

SSH.private:1234

1 password hash cracked, 0 left
```
## Cracking password-protected documents
John the Ripper (JtR) includes a Python script called `office2john.py`, which can be used to extract password hashes from all common Office document formats. These hashes can then be supplied to JtR or Hashcat for offline cracking. 
```
$ office2john.py Protected.docx > protected-docx.hash
$ john --wordlist=rockyou.txt protected-docx.hash
$ john protected-docx.hash --show

Protected.docx:1234

1 password hash cracked, 0 left
```
The process for cracking PDF files is quite similar, as we simply swap out `office2john.py` for `pdf2john.py`.

## Questions
1. Download the attached ZIP archive (cracking-protected-files.zip), and crack the file within. What is the password? **Answer: beethoven**
   - Unzip the file: `$ unzip cracking-protected-files.zip`
   - Locate the `office2john.py` script: `$ locate *2john* | grep office`
   - Get the hash and crack it:
   ```
    $ python /usr/share/john/office2john.py Confidential.xlsx > confidential.hash
    $ john --wordlist=/usr/share/wordlists/rockyou.txt confidential.hash
    $ john confidential.hash --show
    Confidential.xlsx:beethoven

    1 password hash cracked, 0 left
   ```