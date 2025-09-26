# Laudanum, One Webshell to Rule Them All
[Laudanum](https://github.com/jbarcia/Web-Shells) is a repository of ready-made files that can be used to inject onto a victim and receive back access via a reverse shell, run commands on the victim host right from the browser, and more.
## Questions
1. Establish a web shell session with the target using the concepts covered in this section. Submit the full path of the directory you land in. (Format: c:\path\you\land\in) **Answer: c:\windows\system32\inetsrv**
   - Since the web server is IIS (mostly running ASP.NET), upload the [webshell.asp]("D:\Tools\webshells\webshell.asp") and visit it at http://status.inlanefreight.local/files/webshell.asp
   - Type `cd` to print the working directory.
2. Where is the Laudanum aspx web shell located on Pwnbox? Submit the full path. (Format: /path/to/laudanum/aspx) **Answer: /usr/share/laudanum/aspx/shell.aspx**