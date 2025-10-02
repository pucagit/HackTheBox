# Importing Modules
## MSF - Search for Exploits
Note that the hosted file terminations that end in .rb are Ruby scripts that most likely have been crafted specifically for use within msfconsole. We can also filter only by .rb file terminations to avoid output from scripts that cannot run within msfconsole. Note that not all .rb files are automatically converted to msfconsole modules. Some exploits are written in Ruby without having any Metasploit module-compatible code in them. 
```
$ searchsploit -t Nagios3 --exclude=".py"

--------------------------------------------------------------------------------------------------
 Exploit Title                                                             |  Path
--------------------------------------------------------------------------------------------------
Nagios3 - 'history.cgi' Host Command Execution (Metasploit)                | linux/remote/24159.rb
Nagios3 - 'statuswml.cgi' 'Ping' Command Execution (Metasploit)            | cgi/webapps/16908.rb
Nagios3 - 'statuswml.cgi' Command Injection (Metasploit)                   | unix/webapps/9861.rb
--------------------------------------------------------------------------------------------------
Shellcodes: No Results
```
If we want to load the `linux/remote/24159.rb` exploit, use `sudo find / -name "linux/remote/24159.rb"` to locate the path and copy it into the right folder:
```
$ sudo find / -name "24159.rb"
/usr/share/exploitdb/exploits/linux/remote/24159.rb
$ cp /usr/share/exploitdb/exploits/linux/remote/24159.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb
$ msfconsole -m /usr/share/metasploit-framework/modules/
```
Alternatively, we can also launch msfconsole and run the `reload_all` command for the newly installed module to appear in the list. After the command is run and no errors are reported, try either the search [name] function inside msfconsole or directly with the use [module-path] to jump straight into the newly installed module.