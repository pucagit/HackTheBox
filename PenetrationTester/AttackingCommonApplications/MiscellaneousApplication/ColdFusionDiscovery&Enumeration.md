# ColdFusion - Discovery & Enumeration
ColdFusion is a programming language and a web application development platform based on Java. It is used to build dynamic and interactive web applications that can be connected to various APIs and databases such as MySQL, Oracle, and Microsoft SQL Server. ColdFusion Markup Language (`CFML`) is the proprietary programming language used in ColdFusion to develop dynamic web applications.

For instance, the `cfquery` tag can execute SQL statements to retrieve data from a database:

```html
<cfquery name="myQuery" datasource="myDataSource">
  SELECT *
  FROM myTable
</cfquery>
```

Developers can then use the `cfloop` tag to iterate through the records retrieved from the database:

```html
<cfloop query="myQuery">
  <p>#myQuery.firstName# #myQuery.lastName#</p>
</cfloop>
```

ColdFusion exposes a fair few ports by default:

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Port Number</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Protocol</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Description</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">80</td><td class="p-4">HTTP</td><td class="p-4">Used for non-secure HTTP communication between the web server and web browser.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">443</td><td class="p-4">HTTPS</td><td class="p-4">Used for secure HTTP communication between the web server and web browser. Encrypts the communication between the web server and web browser.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">1935</td><td class="p-4">RPC</td><td class="p-4">Used for client-server communication. Remote Procedure Call (RPC) protocol allows a program to request information from another program on a different network device.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">25</td><td class="p-4">SMTP</td><td class="p-4">Simple Mail Transfer Protocol (SMTP) is used for sending email messages.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">8500</td><td class="p-4">SSL</td><td class="p-4">Used for server communication via Secure Socket Layer (SSL).</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">5500</td><td class="p-4">Server Monitor</td><td class="p-4">Used for remote administration of the ColdFusion server.</td></tr></tbody></table>

## Enumeration

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Method</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Description</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Port Scanning</code></td><td class="p-4">ColdFusion typically uses port 80 for HTTP and port 443 for HTTPS by default. So, scanning for these ports may indicate the presence of a ColdFusion server. Nmap might be able to identify ColdFusion during a services scan specifically.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">File Extensions</code></td><td class="p-4">ColdFusion pages typically use ".cfm" or ".cfc" file extensions. If you find pages with these file extensions, it could be an indicator that the application is using ColdFusion.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">HTTP Headers</code></td><td class="p-4">Check the HTTP response headers of the web application. ColdFusion typically sets specific headers, such as "Server: ColdFusion" or "X-Powered-By: ColdFusion", that can help identify the technology being used.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Error Messages</code></td><td class="p-4">If the application uses ColdFusion and there are errors, the error messages may contain references to ColdFusion-specific tags or functions.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Default Files</code></td><td class="p-4">ColdFusion creates several default files during installation, such as "admin.cfm" or "CFIDE/administrator/index.cfm". Finding these files on the web server may indicate that the web application runs on ColdFusion.</td></tr></tbody></table>

```shellsession
$ nmap -p- -sC -Pn 10.129.247.30 --open

Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-13 11:45 GMT
Nmap scan report for 10.129.247.30
Host is up (0.028s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 350.38 seconds
```

As we know, `8500` is a default port that ColdFusion uses for SSL. Navigating to the `IP:8500` lists 2 directories, `CFIDE` and `cfdocs`, in the root, further indicating that ColdFusion is running on port `8500`.

The `/CFIDE/administrator` path, however, loads the ColdFusion 8 Administrator login page. Now we know for certain that `ColdFusion 8` is running on the server.

## Questions
1. What ColdFusion protocol runs on port 5500? **Answer: Server Monitor**