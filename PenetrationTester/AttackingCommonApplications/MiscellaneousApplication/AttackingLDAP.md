# Attacking LDAP
`LDAP` (Lightweight Directory Access Protocol) is a `protocol` used to `access and manage directory information`. A `directory` is a hierarchical data store that contains information about network resources such as `users`, `groups`, `computers`, `printers`, and other devices.

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Use Case</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Description</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Authentication</code></td><td class="p-4">LDAP can be used for <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">central authentication</code>, allowing users to have single login credentials across multiple applications and systems. This is one of the most common use cases for LDAP.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Authorisation</code></td><td class="p-4">LDAP can <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">manage permissions</code> and <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">access control</code> for network resources such as folders or files on a network share. However, this may require additional configuration or integration with protocols like Kerberos.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Directory Services</code></td><td class="p-4">LDAP provides a way to <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">search</code>, <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">retrieve</code>, and <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">modify data</code> stored in a directory, making it helpful for managing large numbers of users and devices in a corporate network. <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">LDAP is based on the X.500 standard</code> for directory services.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Synchronisation</code></td><td class="p-4">LDAP can be used to <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">keep data consistent</code> across multiple systems by <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">replicating changes</code> made in one directory to another.</td></tr></tbody></table>

There are two popular implementations of LDAP: `OpenLDAP`, an open-source software widely used and supported, and `Microsoft Active Directory`. Although LDAP and AD are related, they serve different purposes.

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">LDAP</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Active Directory (AD)</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">A <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">protocol</code> that defines how clients and servers communicate with each other to access and manipulate data stored in a directory service.</td><td class="p-4">A <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">directory server</code> that uses LDAP as one of its protocols to provide authentication, authorisation, and other services for Windows-based networks.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">An <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">open and cross-platform protocol</code> that can be used with different types of directory servers and applications.</td><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Proprietary software</code> that only works with Windows-based systems and requires additional components such as DNS (Domain Name System) and Kerberos for its functionality.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">It has a <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">flexible and extensible schema</code> that allows custom attributes and object classes to be defined by administrators or developers.</td><td class="p-4">It has a <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">predefined schema</code> that follows and extends the X.500 standard with additional object classes and attributes specific to Windows environments. Modifications should be made with caution and care.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Supports <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">multiple authentication mechanisms</code> such as simple bind, SASL, etc.</td><td class="p-4">It supports <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Kerberos</code> as its primary authentication mechanism but also supports NTLM (NT LAN Manager) and LDAP over SSL/TLS for backward compatibility.</td></tr></tbody></table>

LDAP works by using a `client-server architecture`. 

`LDAP requests` are `messages` that clients send to servers to `perform operations` on data stored in a directory service. An LDAP request is comprised of several components:
- `Session connection`: The client connects to the server via an LDAP port (usually 389 or 636).
- `Request type`: The client specifies the operation it wants to perform, such as `bind`, `unbind`, `search`, `compare`, `add`, `delete`, `modify`, etc.
- `Request parameters`: The client provides additional information for the request, such as the `distinguished name` (DN) of the entry to be accessed or modified, the scope and filter of the search query, the attributes and values to be added or changed, etc.
- `Request ID`: The client assigns a unique identifier for each request to match it with the corresponding response from the server.

Once the server receives the request, it processes it and sends back a response message that includes several components:
- `Response type`: The server indicates the operation that was performed in response to the request.
- `Result code`: The server indicates whether or not the operation was successful and why.
- `Matched DN`: If applicable, the server returns the DN of the closest existing entry that matches the request.
- `Referral`: The server returns a URL of another server that may have more information about the request, if applicable.
- `Response data`: The server returns any additional data related to the response, such as the attributes and values of an entry that was searched or modified.

## ldapsearch
For example, `ldapsearch` is a command-line utility used to search for information stored in a directory using the LDAP protocol.

```sh
$ ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"

dn: uid=jdoe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
uid: jdoe
mail: john.doe@example.com

result: 0 Success
```

- Connect to the server `ldap.example.com` on port `389`.
- Bind (authenticate) as `cn=admin,dc=example,dc=com` with password `secret123`.
- Search under the base DN `ou=people,dc=example,dc=com`.
- Use the filter (`mail=john.doe@example.com`) to find entries that have this email address.

## LDAP Injection
`LDAP injection` is an attack that `exploits web applications that use LDAP` for authentication or storing user information. The attacker can inject malicious code or characters into LDAP queries to alter the application's behaviour, bypass security measures, and access sensitive data stored in the LDAP directory.

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Input</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Description</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">*</code></td><td class="p-4">An asterisk <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">*</code> can <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">match any number of characters</code>.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">( )</code></td><td class="p-4">Parentheses <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">( )</code> can <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">group expressions</code>.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">|</code></td><td class="p-4">A vertical bar <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">|</code> can perform <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">logical OR</code>.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">&amp;</code></td><td class="p-4">An ampersand <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">&amp;</code> can perform <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">logical AND</code>.</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">(cn=*)</code></td><td class="p-4">Input values that try to bypass authentication or authorisation checks by injecting conditions that <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">always evaluate to true</code> can be used. For example, <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">(cn=*)</code> or <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">(objectClass=*)</code> can be used as input values for a username or password fields.</td></tr></tbody></table>

## Enumeration
### nmap

```sh
$ nmap -p- -sC -sV --open --min-rate=1000 10.129.204.229

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-23 14:43 SAST
Nmap scan report for 10.129.204.229
Host is up (0.18s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X
```

nmap detects a `http` server running on port `80` and an `ldap` server running on port `389`

### Injection
As `OpenLDAP` runs on the server, it is safe to assume that the web application running on port 80 uses LDAP for authentication.

## Questions
1. After bypassing the login, what is the website "Powered by"? **Answer: w3.css**
   - Login with any user account using `username=*&password=*`