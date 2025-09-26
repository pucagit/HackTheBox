# Antak Webshell
## ASPX Explained
**Active Server Page Extended** (ASPX) is a file type/extension written for Microsoft's ASP.NET Framework. On a web server running the ASP.NET framework, web form pages can be generated for users to input data. On the server side, the information will be converted into HTML. We can take advantage of this by using an ASPX-based web shell to control the underlying Windows operating system.

## Antak Webshell
Antak is a web shell built in ASP.Net included within the [Nishang project](https://github.com/samratashok/nishang/tree/master/Antak-WebShell). Antak utilizes PowerShell to interact with the host, making it great for acquiring a web shell on a Windows server. The UI is even themed like PowerShell.

## Questions
1. Where is the Antak webshell located on Pwnbox? Submit the full path. (Format:/path/to/antakwebshell) **Answer: /usr/share/nishang/Antak-WebShell/antak.aspx**
2. Establish a web shell with the target using the concepts covered in this section. Submit the name of the user on the target that the commands are being issued as. In order to get the correct answer you must navigate to the web shell you upload using the vHost name. **Answer: iis apppool\status**
   - Upload the `antak.aspx` file and execute `whoami` on the powershell interface.