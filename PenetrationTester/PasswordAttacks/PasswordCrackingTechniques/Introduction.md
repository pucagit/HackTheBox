# Introduction to Password Cracking
Passwords are commonly hashed when stored, in order to provide some protection in the event they fall into the hands of an attacker. Hashing is a mathematical function which transforms an arbitrary number of input bytes into a (typically) fixed-size output; common examples of hash functions are `MD5`, and `SHA-256`.

```
$ echo -n Soccer06! | md5sum
40291c1d19ee11a7df8495c4cccefdfa  -

$ echo -n Soccer06! | sha256sum
a025dc6fabb09c2b8bfe23b5944635f9b68433ebd9a1a09453dd4fee00766d93  -
```
Hash functions are designed to work in one direction. This means it should not be possible to figure out what the original password was based on the hash alone. When attackers attempt to do this, it is called **password cracking**. Common techniques are to use **rainbow tables**, to perform **dictionary attacks**, and typically as a last resort, to perform brute-force attacks.
## Ranbow tables
Rainbow tables are large **pre-compiled maps** of input and output values for a given hash function. These can be used to very quickly identify the password if its corresponding hash has already been mapped.

Because rainbow tables are such a powerful attack, salting is used. A **salt**, in cryptographic terms, is a random sequence of bytes added to a password before it is hashed.

A salt is not a secret value — when a system goes to check an authentication request, it needs to know what salt was used so that it can check if the password hash matches. For this reason, salts are typically prepended to corresponding hashes. The reason this technique works against rainbow tables is that even if the correct password has been mapped, the combination of salt and password has likely not (especially if the salt contains non-printable characters).
## Questions
1. What is the SHA1 hash for `Academy#2025`? **Answer: 750fe4b402dc9f91cedf09b652543cd85406be8c** 
   - `$ echo -n "Academy#2025" | sha1sum`
--- 

# Introduction to John The Ripper
[John the Ripper](https://github.com/openwall/john) (aka. JtR aka. john) is a well-known penetration testing tool used for cracking passwords through various attacks including brute-force and dictionary.
## Cracking modes
**Single crack mode**

A **rule-based** cracking technique that is most useful when targeting Linux credentials. It generates password candidates based on the victim's username, home directory name, and GECOS values (full name, room number, phone number, etc.). These strings are run against a large set of rules that apply common string modifications seen in passwords.

For example we came accross the `passwd` file and notice the username `rolf`, the real name `Rolf Sebastian`. Single crack mode will use this information to generate candidate passwords and test them against the hash. We can run the attack with the following command:
```
$ john --single passwd
[...SNIP...]        (r0lf)     
1g 0:00:00:00 DONE 1/3 (2025-04-10 07:47) 12.50g/s 5400p/s 5400c/s 5400C/s NAITSABESFL0R..rSebastiannaitsabeSr
```
**Wordlist mode**

Wordlist mode is used to crack passwords with a dictionary attack, meaning it attempts all passwords in a supplied wordlist against the password hash.
```
$ john --wordlist=<wordlist_file> <hash_file>
```
Rules, either custom or built-in, can be specified by using the `--rules` argument.

**Incremental mode**

Incremental mode is a powerful, brute-force-style password cracking mode that generates candidate passwords based on a statistical model (Markov chains). It is designed to test all character combinations defined by a specific character set, prioritizing more likely passwords based on training data.
```
$ john --incremental <hash_file>
```

## Identifying hash formats
One way to get an idea is to consult [JtR's sample hash documentation](https://openwall.info/wiki/john/sample-hashes), or [this list by PentestMonkey](https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats). Both sources list multiple example hashes as well as the corresponding JtR format. Another option is to use a tool like [hashID](https://github.com/psypanda/hashID), which checks supplied hashes against a built-in list to suggest potential formats. By adding the `-j` flag, hashID will, in addition to the hash format, list the corresponding JtR format:
```
$ hashid -j <hash>
```

JtR supports hundreds of hash formats, some of which are listed in the table below. The `--format` argument can be supplied to instruct JtR which format target hashes have.

## Cracking files
It is also possible to crack password-protected or encrypted files with JtR. Multiple `"2john"` tools come with JtR that can be used to process files and produce hashes compatible with JtR. The generalized syntax for these tools is:
```
$ <tool> <file_to_crack> > file.hash
```
Some of the tools included with JtR are:
|Tool|Description|
|-|-|
|`pdf2john`|Converts PDF documents for John|
|`ssh2john`|Converts SSH private keys for John|
|`mscash2john`|Converts MS Cash hashes for John|
|`keychain2john`|Converts OS X keychain files for John|
|`rar2john`|Converts RAR archives for John|
|`pfx2john`|Converts PKCS#12 files for John|
|`truecrypt_volume2john`|Converts TrueCrypt volumes for John|
|`keepass2john`|Converts KeePass databases for John|
|`vncpcap2john`|Converts VNC PCAP files for John|
|`putty2john`|Converts PuTTY private keys for John|
|`zip2john`|Converts ZIP archives for John|
|`hccap2john`|Converts WPA/WPA2 handshake captures for John|
|`office2john`|Converts MS Office documents for John|
|`wpa2john`|Converts WPA/WPA2 handshakes for John|

## Questions
1. Use single-crack mode to crack r0lf's password. **Answer: NAITSABES**
   - Create a file with this content: `r0lf:$6$ues25dIanlctrWxg$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash` (don't use `echo` as it would eval the `$` sign)
   - Run JtR in single mode: `$ john --single <file_name>`
2. Use wordlist-mode with rockyou.txt to crack the RIPEMD-128 password. **Answer: 50cent**
   - Create a file with the hash as the content: `193069ceb0461e1d40d216e32c79c704`
   - Run JtR in wordlist mode and force for RIPEMD-128 format: `$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=ripemd-128 <file_name>`

# Introduction to Hashcat
The general syntax used to run hashcat is as follows:
```
$ hashcat -a 0 -m 0 <hashes> [wordlist, rule, mask, ...]
```
- `-a` is used to specify the attack mode
- `-m` is used to specify the hash type
- `<hashes>` is a either a hash string, or a file containing one or more password hashes of the same type
[wordlist, rule, mask, ...] is a placeholder for additional arguments that depend on the attack mode
## Hash types
The hashcat website hosts a comprehensive [list of example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) which can assist in manually identifying an unknown hash type and determining the corresponding Hashcat hash mode identifier.

Alternatively, [hashID](https://github.com/psypanda/hashID) can be used to quickly identify the hashcat hash type by specifying the `-m` argument.
```
$ hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
```
## Attack modes
**Dictionary attack**

Dictionary attack (`-a 0`) is, as the name suggests, a dictionary attack. The user provides password hashes and a wordlist as input, and Hashcat tests each word in the list as a potential password until the correct one is found or the list is exhausted.

If we weren't able to crack it using `rockyou.txt` alone, we might apply some common rule-based transformations. One ruleset we could try is `best64.rule` (`ls -l /usr/share/hashcat/rules`), which contains 64 standard password modifications—such as appending numbers or substituting characters with their "leet" equivalents. To perform this kind of attack, we would append the `-r <ruleset>` option to the command, as shown below:
```
$ hashcat -a 0 -m 0 <hash> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```
**Mask attack**

Mask attack (`-a 3`) is a type of brute-force attack in which the keyspace is explicitly defined by the user. For example, if we know that a password is eight characters long, rather than attempting every possible combination, we might define a mask that tests combinations of six letters followed by two numbers.

A mask is defined by combining a sequence of symbols, each representing a built-in or custom character set. Hashcat includes several built-in character sets:
|Symbol|Charset|
|-|-|
|`?l`|abcdefghijklmnopqrstuvwxyz|
|`?u`|ABCDEFGHIJKLMNOPQRSTUVWXYZ|
|`?d`|0123456789|
|`?h`|0123456789abcdef|
|`?H`|0123456789ABCDEF|
|`?s`|«space»!"#$%&'()*+,-./:;<=>?@[]^_`{|
|`?a`|?l?u?d?s|
|`?b`|0x00 - 0xff|

Custom charsets can be defined with the `-1`, `-2`, `-3`, and `-4` arguments, then referred to with `?1`, `?2`, `?3`, and `?4`.

Let's say that we specifically want to try passwords which start with an **uppercase letter**, continue with **four lowercase letters**, **a digit**, and then **a symbol**. The resulting hashcat mask would be `?u?l?l?l?l?d?s`.
```
$ hashcat -a 3 -m 0 <hash> '?u?l?l?l?l?d?s'
```

## Questions
1. Use a dictionary attack to crack the first password hash. (Hash: e3e3ec5831ad5e7288241960e5d4fdb8) **Answer: crazy!**
   - `$ hashid -m e3e3ec5831ad5e7288241960e5d4fdb8` → detect possible MD5.
   - `$ hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt`
2. Use a dictionary attack with rules to crack the second password hash. (Hash: 1b0556a75770563578569ae21392630c) **Answer: c0wb0ys1**
   - `$ hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule`
3. Use a mask attack to crack the third password hash. (Hash: 1e293d6912d074c0fd15844d803400dd) **Answer: Mouse5!**
   - `$ hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'`