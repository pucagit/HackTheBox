# Domain Trusts Primer
## Domain Trusts Overview
A trust is used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources in (or perform administrative tasks) another domain, outside of the main domain where their account resides. A trust creates a link between the authentication systems of two domains and may allow either one-way or two-way (bidirectional) communication. An organization can create various types of trusts:

- `Parent-child`: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain `corp.inlanefreight.local` could authenticate into the parent domain `inlanefreight.local`, and vice-versa.
- `Cross-link`: A trust between child domains to speed up authentication.
- `External`: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering or filters out authentication requests (by SID) not from the trusted domain.
- `Tree-root`: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
- `Forest`: A transitive trust between two forest root domains.
- `ESAE`: A bastion forest used to manage Active Directory.

Trusts can be transitive or non-transitive:
- A `transitive` trust means that trust is extended to objects that the child domain trusts. For example, let's say we have three domains. In a transitive relationship, if Domain A has a trust with Domain B, and Domain B has a transitive trust with Domain C, then Domain A will automatically trust Domain C.
- In a `non-transitive` trust, the child domain itself is the only one trusted.

### Trust Table Side By Side

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Transitive</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Non-Transitive</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Shared, 1 to many</td><td class="p-4">Direct trust</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">The trust is shared with anyone in the forest</td><td class="p-4">Not extended to next level child domains</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4">Forest, tree-root, parent-child, and cross-link trusts are transitive</td><td class="p-4">Typical for external or custom trust setups</td></tr></tbody></table>

Trusts can be set up in two directions: one-way or two-way (bidirectional).

- `One-way trust`: Users in a `trusted` domain can access resources in a trusting domain, not vice-versa.
- `Bidirectional trust`: Users from both trusting domains can access resources in the other domain. 

![alt text](trusts-diagram.png)

## Enumerating Trust Relationships
### Using Get-ADTrust
We can use the [Get-ADTrust](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps) cmdlet to enumerate domain trust relationships. This is especially helpful if we are limited to just using built-in tools.

```pwsh
PS C:\htb> Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : f48a1169-2e58-42c1-ba32-a6ccb10057ec
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=FREIGHTLOGISTICS.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : True
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : FREIGHTLOGISTICS.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : 1597717f-89b7-49b8-9cd9-0801d52475ca
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : FREIGHTLOGISTICS.LOCAL
TGTDelegation           : False
TrustAttributes         : 8
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```

The above output shows that our current domain `INLANEFREIGHT.LOCAL` has two domain trusts. The first is with `LOGISTICS.INLANEFREIGHT.LOCAL`, and the `IntraForest` property shows that this is a child domain, and we are currently positioned in the root domain of the forest. The second trust is with the domain `FREIGHTLOGISTICS.LOCAL`, and the `ForestTransitive` property is set to `True`, which means that this is a forest trust or external trust. We can see that both trusts are set up to be bidirectional, meaning that users can authenticate back and forth across both trusts. 

### Checking for Existing Trusts using Get-DomainTrust

```pwsh
PS C:\htb> Get-DomainTrust 

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM
```

### Using Get-DomainTrustMapping
PowerView can be used to perform a domain trust mapping and provide information such as the type of trust (parent/child, external, forest) and the direction of the trust (one-way or bidirectional).

```pwsh
PS C:\htb> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM

SourceName      : FREIGHTLOGISTICS.LOCAL
TargetName      : INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:08 PM
WhenChanged     : 2/27/2022 12:02:41 AM

SourceName      : LOGISTICS.INLANEFREIGHT.LOCAL
TargetName      : INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM
```

### Checking Users in the Child Domain using Get-DomainUser
From here, we could begin performing enumeration across the trusts. For example, we could look at all users in the child domain:

```pwsh
PS C:\htb> Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName

samaccountname
--------------
htb-student_adm
Administrator
Guest
lab_adm
krbtgt
```

### Using netdom to query domain trust
Another tool we can use to get Domain Trust is `netdom`. The `netdom query` can retrieve information about the domain, including a list of workstations, servers, and domain trusts.

```pwsh
C:\htb> netdom query /domain:inlanefreight.local trust
Direction Trusted\Trusting domain                         Trust type
========= =======================                         ==========

<->       LOGISTICS.INLANEFREIGHT.LOCAL
Direct
 Not found

<->       FREIGHTLOGISTICS.LOCAL
Direct
 Not found

The command completed successfully.
```

### Using netdom to query domain controllers

```pwsh
C:\htb> netdom query /domain:inlanefreight.local dc
List of domain controllers with accounts in the domain:

ACADEMY-EA-DC01
The command completed successfully.
```

### Using netdom to query workstations and servers

```pwsh
C:\htb> netdom query /domain:inlanefreight.local workstation
List of workstations with accounts in the domain:

ACADEMY-EA-MS01
ACADEMY-EA-MX01      ( Workstation or Server )

SQL01      ( Workstation or Server )
ILF-XRG      ( Workstation or Server )
MAINLON      ( Workstation or Server )
CISERVER      ( Workstation or Server )
INDEX-DEV-LON      ( Workstation or Server )
...SNIP...
```

## Questions
RDP to **10.129.52.133** (ACADEMY-EA-MS01), with user `htb-student` and password `Academy_student_AD!`
1. What is the child domain of INLANEFREIGHT.LOCAL? (format: FQDN, i.e., DEV.ACME.LOCAL) **Answer: LOGISTICS.INLANEFREIGHT.LOCAL**
   - Enumerate domain trust relationships using Get-ADTrust and found the domain with `IntraForest: True`:
        ```pwsh
        PS C:\Tools> Import-Module activedirectory
        PS C:\Tools> Get-ADTrust -Filter *


        Direction               : BiDirectional
        DisallowTransivity      : False
        DistinguishedName       : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
        ForestTransitive        : False
        IntraForest             : True
        IsTreeParent            : False
        IsTreeRoot              : False
        Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
        ObjectClass             : trustedDomain
        ObjectGUID              : f48a1169-2e58-42c1-ba32-a6ccb10057ec
        SelectiveAuthentication : False
        SIDFilteringForestAware : False
        SIDFilteringQuarantined : False
        Source                  : DC=INLANEFREIGHT,DC=LOCAL
        Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
        TGTDelegation           : False
        TrustAttributes         : 32
        TrustedPolicy           :
        TrustingPolicy          :
        TrustType               : Uplevel
        UplevelOnly             : False
        UsesAESKeys             : False
        UsesRC4Encryption       : False

        Direction               : BiDirectional
        DisallowTransivity      : False
        DistinguishedName       : CN=FREIGHTLOGISTICS.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
        ForestTransitive        : True
        IntraForest             : False
        IsTreeParent            : False
        IsTreeRoot              : False
        Name                    : FREIGHTLOGISTICS.LOCAL
        ObjectClass             : trustedDomain
        ObjectGUID              : 1597717f-89b7-49b8-9cd9-0801d52475ca
        SelectiveAuthentication : False
        SIDFilteringForestAware : False
        SIDFilteringQuarantined : False
        Source                  : DC=INLANEFREIGHT,DC=LOCAL
        Target                  : FREIGHTLOGISTICS.LOCAL
        TGTDelegation           : False
        TrustAttributes         : 8
        TrustedPolicy           :
        TrustingPolicy          :
        TrustType               : Uplevel
        UplevelOnly             : False
        UsesAESKeys             : False
        UsesRC4Encryption       : False
        ```
2. What domain does the INLANEFREIGHT.LOCAL domain have a forest transitive trust with? **Answer: FREIGHTLOGISTICS.LOCAL**
   - Read above result and find that `FREIGHTLOGISTICS.LOCAL` has `ForestTransitive: True`
3. What direction is this trust? **Answer: BiDirectional**
   - Read above result and find that `FREIGHTLOGISTICS.LOCAL` has `Direction: BiDirectional`