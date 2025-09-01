# FTP (port 20,21)
In an FTP connection, two channels are opened. First, the client and server establish a control channel through TCP port 21. The client sends commands to the server, and the server returns status codes. Then both communication participants can establish the data channel via TCP port 20. This channel is used exclusively for data transmission, and the protocol watches for errors during this process.

One of the most used FTP servers on Linux-based distributions is vsFTPd. The default configuration of vsFTPd can be found in `/etc/vsftpd.conf`. In addition, there is a file called `/etc/ftpusers` that we also need to pay attention to, as this file is used to deny certain users access to the FTP service

# Questions: 
1. Which version of the FTP server is running on the target system? Submit the entire banner as the answer.
- `$ nmap -sC -sV -p21 <ip>`
2. Enumerate the FTP server and find the flag.txt file. Submit the contents of it as the answer.
- `ftp> ls` to find the file, and `ftp> get flag.txt ~/flag.txt` to get the file

