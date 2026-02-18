# Writing Custom Wordlists and Rules
## Custom Hashcat rules
Let's look at a simple example using a password list with only one entry.
```
[!bash!]$ cat password.list

password
```
We can use Hashcat to combine lists of potential names and labels with specific mutation rules to create custom wordlists. Hashcat uses a specific syntax to define characters, words, and their transformations. The complete syntax is documented in the official [Hashcat rule-based attack documentation](https://hashcat.net/wiki/doku.php?id=rule_based_attack), but the examples below are sufficient to understand how Hashcat mutates input words.
|Function|Description|
|-|-|
|`:`|Do nothing|
|`l`|Lowercase all letters|
|`u`|Uppercase all letters|
|`c`|Capitalize the first letter and lowercase others|
|`sXY`|Replace all instances of X with Y|
|`:$!`|Add the exclamation character at the end|
Each rule is written on a new line and determines how a given word should be transformed. If we write the functions shown above into a file, it may look like this:
```
[!bash!]$ cat custom.rule

:               # 1. Do nothing
c               # 2. Capitalize the first letter and lowercase others
so0             # 3. Swap all 'o' with '0'
c so0           # 4. Capitalize the first letter and lowercase others and swap all 'o' with '0'
sa@             # 5. Swap all 'a' with '@'
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```
We can use the following command to apply the rules in custom.rule to each word in password.list and store the mutated results in mut_password.list.
```
[!bash!]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```
In this case, the single input word will produce fifteen mutated variants.
```
[!bash!]$ cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
````
Hashcat and JtR both come with pre-built rule lists that can be used for password generation and cracking. One of the most effective and widely used rulesets is `best64.rule`, which applies common transformations that frequently result in successful password guesses. 

## Generating wordlists using CeWL
We can use a tool called [CeWL](https://github.com/digininja/CeWL) to scan potential words from a company's website and save them in a separate list. We can then combine this list with the desired rules to create a customized password list—one that has a higher probability of containing the correct password for an employee. We specify some parameters, like the depth to spider (`-d`), the minimum length of the word (`-m`), the storage of the found words in lowercase (`--lowercase`), as well as the file where we want to store the results (`-w`).
```
[!bash!]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
[!bash!]$ wc -l inlane.wordlist

326
```

## Exercise
For this sections exercise, imagine that we compromised the password hash of a `work email` belonging to `Mark White`. After performing a bit of OSINT, we have gathered the following information about Mark:

- He was born on `August 5, 1998`
- He works at `Nexura, Ltd`.
- The company's password policy requires passwords to be at least 12 characters long, to contain at least one uppercase letter, at least one lowercase letter, at least one symbol and at least one number
- He lives in `San Francisco, CA, USA`
- He has a pet cat named `Bella`
- He has a wife named `Maria`
- He has a son named `Alex`
- He is a big fan of `baseball`

The password hash is: `97268a8ae45ac7d15c3cea4ce6ea550b`. Use the techniques covered in this section to generate a custom wordlist and ruleset targeting Mark specifically, and crack the password.

## Questions
1. What is Mark's password? **Answer: Baseball1998!**
   - Build wordlist containing the exercise's words:
        ```
        $ cat mark.wordlist
        work
        email
        Mark
        White
        August
        5
        1998
        Nexura
        Ltd
        San
        Francisco
        CA
        USA
        Bella
        Maria
        Alex
        baseball
        ```
   - Write custom mutation script that combines two words, perform mutation one them and only output those with length >= 12:
        ```
        $ cat mutation.py
        #!/usr/bin/env python3
        import sys

        if len(sys.argv) != 2:
            print("usage: python pairwise.py wordlist.txt", file=sys.stderr)
            sys.exit(1)

        words = [w.strip() for w in open(sys.argv[1], encoding="utf-8") if w.strip()]

        for i, a in enumerate(words):
            for j, b in enumerate(words):
                if i == j:
                    continue
                if len(a+b) >= 12:
                    print(a + b)
        ```
   - Write custom rule:
        ```
        $ cat company.rule
        c $!
        c $@
        c $#
        c $%
        c $^
        c $&
        c $*
        c $(
        c $)
        c $1
        c $2
        c $3
        c $4
        c $5
        c $6
        c $7
        c $8
        c $9
        c $0
        ```
   - Apply the rule to the `mutation.wordlist`:
        ```
        $ hashcat --force mutation.wordlist -r company.rule --stdout | sort -u > final.wordlist
        ```
   - Perform password cracking:
        ```
        $ hashcat -a 0 -m 0 97268a8ae45ac7d15c3cea4ce6ea550b final.wordlist
        ```
        
