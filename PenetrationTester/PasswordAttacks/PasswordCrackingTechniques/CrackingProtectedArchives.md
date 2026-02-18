# Cracking Protected Archives
There are many types of archive files. Some of the more commonly encountered file extensions include `tar`, `gz`, `rar`, `zip`, `vmdb/vmx`, `cpt`, `truecrypt`, `bitlocker`, `kdbx`, `deb`, `7z`, and `gzip`.

A comprehensive list of archive file types can be found on [FileInfo](https://fileinfo.com/filetypes/compressed). Rather than typing them out manually, we can also query the data using a one-liner, apply filters as needed, and save the results to a file.
```
$ curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt

.mint
.zhelp
.b6z
.fzpz
.zst
.apz
.ufs.uzip
.vrpackage
.sfg
.gzip
.xapk
.rar
.pkg.tar.xz
<SNIP>
```
## Cracking ZIP files
```
$ zip2john ZIP.zip > zip.hash
$ john --wordlist=rockyou.txt zip.hash
$ john zip.hash --show
```
## Cracking OpenSSL encrypted GZIP files
`Openssl` can be used to encrypt files in the GZIP format. To determine the actual format of a file, we can use the file command, which provides detailed information about its contents.
```
$ file GZIP.gzip 

GZIP.gzip: openssl enc'd data with salted password
```
A more reliable approach is to use the openssl tool within a for loop that attempts to extract the contents directly, succeeding only if the correct password is found.

The following one-liner may produce several GZIP-related error messages, which can be safely ignored. If the correct password list is used, as in this example, we will see another file successfully extracted from the archive.
```
$ for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done

gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now

gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now
<SNIP>
$ ls

customers.csv  GZIP.gzip  rockyou.txt
```
## Cracking BitLocker-encrypted drives
**BitLocker** is a full-disk encryption feature developed by Microsoft for the Windows operating system. Available since Windows Vista, it uses the **AES encryption** algorithm with either **128-bit** or **256-bit** key lengths. If the password or PIN used for BitLocker is forgotten, decryption can still be performed using a recovery key—a 48-digit string generated during the setup process.

To crack a BitLocker encrypted drive, we can use a script called `bitlocker2john` to **four** different hashes: the first two correspond to the BitLocker password, while the latter two represent the recovery key. Because the recovery key is very long and randomly generated, it is generally not practical to guess—unless partial knowledge is available. Therefore, we will focus on cracking the password using the first hash (`$bitlocker$0$...`).
```
$ bitlocker2john -i Backup.vhd > backup.hashes
$ grep 'bitlocker\$0' backup.hashes > backup.hash
$ hashcat -a 0 -m 22100 $(cat backup.hash) /usr/share/wordlists/rockyou.txt
```
### Mounting BitLocker-encrypted drives in Windows
The easiest method for mounting a BitLocker-encrypted virtual drive on Windows is to double-click the `.vhd` file. Since it is encrypted, Windows will initially show an error. After mounting, simply double-click the BitLocker volume to be prompted for the password.
### Mounting BitLocker-encrypted drives in Linux (or macOS)
It is also possible to mount BitLocker-encrypted drives in Linux (or macOS). To do this, we can use a tool called `dislocker`. First, we need to install the package using apt:
```
$ sudo apt-get install dislocker
```
Next, we create two folders which we will use to mount the VHD.
```
$ sudo mkdir -p /media/bitlocker
$ sudo mkdir -p /media/bitlockermount
```
We then use `losetup` to configure the VHD as loop device, decrypt the drive using `dislocker`, and finally mount the decrypted volume:
```
$ sudo losetup -f -P Backup.vhd
$ sudo dislocker /dev/loop0p2 -u1234qwer -- /media/bitlocker
$ sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
```
If everything was done correctly, we can now browse the files:
```
$ cd /media/bitlockermount/
$ ls -la
```
Once we have analyzed the files on the mounted drive, we can unmount it using the following commands:
```
$ sudo umount /media/bitlockermount
$ sudo umount /media/bitlocker
```
## Questions
1. Run the above target then navigate to http://ip:port/download, then extract the downloaded file. Inside, you will find a password-protected VHD file. Crack the password for the VHD and submit the recovered password as your answer. **Answer: francisco**
   - Download the zip file using: `$ wget http://ip:port/download`
   - Unzip it using: `$ unzip download`
   - Get the hash of `Private.vhd` and crack it:
        ```
        $ bitlocker2john -i Private.vhd > private.hashes
        $ grep 'bitlocker\$0' private.hashes > private.hash
        $ hashcat -a 0 -m 22100 $(cat private.hash) /usr/share/wordlists/rockyou.txt
        ```
2. Mount the BitLocker-encrypted VHD and enter the contents of flag.txt as your answer. **Answer: 43d95aeed3114a53ac66f01265f9b7af**
   - On Windows, Right Click the `Start` Menu → Choose `Disk Management` → Click on `Action` → `Attach VHD` → Browse to the `Private.vhd` file → `OK` → Click on the newly created volume → Enter the password and read the `flag.txt`.