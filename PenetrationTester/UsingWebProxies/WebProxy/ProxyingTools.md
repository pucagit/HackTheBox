# Proxying Tools
## Questions
1. Try running 'auxiliary/scanner/http/http_put' in Metasploit on any website, while routing the traffic through Burp. Once you view the requests sent, what is the last line in the request? **Answer: msf test file**
   - Run the module with these options:
        ```
        [msf](Jobs:0 Agents:0) auxiliary(scanner/http/http_put) >> options

        Module options (auxiliary/scanner/http/http_put):

        Name      Current Setting        Required  Description
        ----      ---------------        --------  -----------
        ACTION    PUT                    yes       PUT or DELETE
        FILEDATA  msf test file          no        The data to upload into the file
        FILENAME  msf_http_put_test.txt  yes       The file to attempt to write or delete
        PATH      /                      yes       The path to attempt to write or delete
        Proxies   http:127.0.0.1:8080    no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, sapni, socks5h, http
        RHOSTS    154.57.164.81          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
        RPORT     30781                  yes       The target port (TCP)
        SSL       false                  no        Negotiate SSL/TLS for outgoing connections
        THREADS   1                      yes       The number of concurrent threads (max one per host)
        VHOST                            no        HTTP server virtual host


        Auxiliary action:

        Name  Description
        ----  -----------
        PUT   Upload local file



        View the full module info with the info, or info -d command.

        [msf](Jobs:0 Agents:0) auxiliary(scanner/http/http_put) >> run
        [-] 154.57.164.81: File doesn't seem to exist. The upload probably failed
        [*] Scanned 1 of 1 hosts (100% complete)
        [*] Auxiliary module execution completed
        ```
   - Observe the request got routed through Burp:
        ```
        PUT /msf_http_put_test.txt HTTP/1.1
        Host: 154.57.164.81:30781
        User-Agent: Mozilla/5.0 (iPad; CPU OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1
        Content-Type: text/plain
        Content-Length: 13
        Connection: keep-alive

        msf test file
        ```