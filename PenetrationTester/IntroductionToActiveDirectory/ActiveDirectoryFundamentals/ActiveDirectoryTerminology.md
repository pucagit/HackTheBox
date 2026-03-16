# Active Directory Terminology
## Object
An object can be defined as ANY resource present within an Active Directory environment such as OUs, printers, users, domain controllers, etc.

## Attributes
Every object in Active Directory has an associated set of [attributes](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all) used to define characteristics of the given object. A computer object contains attributes such as the hostname and DNS name. All attributes in AD have an associated LDAP name that can be used when performing LDAP queries, such as `displayName` for `Full Name` and `given name` for `First Name`.

## Schema
The Active Directory [schema](https://docs.microsoft.com/en-us/windows/win32/ad/schema) is essentially the blueprint of any enterprise environment. It defines what types of objects can exist in the AD database and their associated attributes. It lists definitions corresponding to AD objects and holds information about each object. 

## Domain
A domain is a logical group of objects such as computers, users, OUs, groups, etc. Domains can operate entirely independently of one another or be connected via trust relationships.

## Forest
A forest is a collection of Active Directory domains. It is the topmost container and contains all of the AD objects introduced below, including but not limited to domains, users, groups, computers, and Group Policy objects. Each forest operates independently but may have various trust relationships with other forests.

## Tree
A tree is a collection of Active Directory domains that begins at a single root domain. A forest is a collection of AD trees. Each domain in a tree shares a boundary with the other domains. A parent-child trust relationship is formed when a domain is added under another domain in a tree. Two trees in the same forest cannot share a name (namespace). 

## Container
Container objects hold other objects and have a defined place in the directory subtree hierarchy.

## Leaf
Leaf objects do not contain other objects and are found at the end of the subtree hierarchy.

## Global Unique Identifier (GUID)
A [GUID](https://docs.microsoft.com/en-us/windows/win32/adschema/a-objectguid) is a unique 128-bit value assigned when a domain user or group is created. This GUID value is unique across the enterprise, similar to a MAC address. Every single object created by Active Directory is assigned a GUID, not only user and group objects. The GUID is stored in the `ObjectGUID` attribute. When querying for an AD object (such as a user, group, computer, domain, domain controller, etc.), we can query for its objectGUID value using PowerShell or search for it by specifying its distinguished name, GUID, SID, or SAM account name. GUIDs are used by AD to identify objects internally. Searching in Active Directory by GUID value is probably the most accurate and reliable way to find the exact object you are looking for, especially if the global catalog may contain similar matches for an object name. The `ObjectGUID` property never changes and is associated with the object for as long as that object exists in the domain.

## Security principals
[Security principals](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals) are anything that the operating system can authenticate, including users, computer accounts, or even threads/processes that run in the context of a user or computer account. In AD, security principals are domain objects that can manage access to other resources within the domain. We can also have local user accounts and security groups used to control access to resources on only that specific computer. These are not managed by AD but rather by the [Security Accounts Manager (SAM)](https://en.wikipedia.org/wiki/Security_Account_Manager).

## Security Identifier (SID)
A s[ecurity identifier](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals), or SID is used as a unique identifier for a security principal or security group. Every account, group, or process has its own unique SID, which, in an AD environment, is issued by the domain controller and stored in a secure database. A SID can only be used once. Even if the security principal is deleted, it can never be used again in that environment to identify another user or group. When a user logs in, the system creates an access token for them which contains the user's SID, the rights they have been granted, and the SIDs for any groups that the user is a member of. This token is used to check rights whenever the user performs an action on the computer. There are also [well-known SIDs](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers) that are used to identify generic users and groups. These are the same across all operating systems. An example is the `Everyone` group.


## Distinguished Name (DN)
A Distinguished Name (DN) describes the full path to an object in AD (such as `cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local`). In this example, the user bjones works in the IT department of the company Inlanefreight, and his account is created in an Organizational Unit (OU) that holds accounts for company employees. The Common Name (CN) bjones is just one way the user object could be searched for or accessed within the domain.

## Relative Distinguished Name (RDN)
A [Relative Distinguished Name (RDN)](https://docs.microsoft.com/en-us/windows/win32/ad/object-names-and-identities) is a single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy. 

## sAMAccountName
The [sAMAccountName](https://docs.microsoft.com/en-us/windows/win32/ad/naming-properties#samaccountname) is the user's logon name. Here it would just be `bjones`. It must be a unique value and 20 or fewer characters.

## userPrincipalName
The [userPrincipalName](https://social.technet.microsoft.com/wiki/contents/articles/52250.active-directory-user-principal-name.aspx) attribute is another way to identify users in AD. This attribute consists of a prefix (the user account name) and a suffix (the domain name) in the format of `bjones@inlanefreight.local`. This attribute is not mandatory.

## FSMO Roles
Early Active Directory (AD) systems had problems when multiple Domain Controllers (DCs) tried to make changes at the same time, causing conflicts. Microsoft first used a **“last writer wins”** model, but this could overwrite important changes. They then moved to a **single master DC** to control changes, but this created a **single point of failure** if that DC went down.

To fix this, Microsoft introduced **Flexible Single Master Operation (FSMO) roles**, which distribute specific responsibilities among DCs while allowing all DCs to continue **authentication and authorization**.

There are **five FSMO roles**:

* **Schema Master** – one per forest
* **Domain Naming Master** – one per forest
* **RID Master** – one per domain
* **PDC Emulator** – one per domain
* **Infrastructure Master** – one per domain

In a new AD forest, **all five roles are initially assigned to the first DC**. When new domains are added, they receive the **RID Master, PDC Emulator, and Infrastructure Master** roles. Administrators can transfer these roles if needed to ensure **proper replication and reliable AD operations**.

## Global Catalog
A [global catalog (GC)](https://docs.microsoft.com/en-us/windows/win32/ad/global-catalog) is a domain controller that stores copies of ALL objects in an Active Directory forest. The GC stores a full copy of all objects in the current domain and a partial copy of objects that belong to other domains in the forest. Standard domain controllers hold a complete replica of objects belonging to its domain but not those of different domains in the forest. The GC allows both users and applications to find information about any objects in ANY domain in the forest. GC is a feature that is enabled on a domain controller and performs the following functions:

- Authentication (provided authorization for all groups that a user account belongs to, which is included when an access token is generated)
- Object search (making the directory structure within a forest transparent, allowing a search to be carried out across all domains in a forest by providing just one attribute about an object.)

## Read-Only Domain Controller (RODC)
A [Read-Only Domain Controller (RODC)](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema) is used to provide Active Directory services in locations where security or connectivity is limited, such as branch offices. It contains a read-only copy of the AD database and DNS, meaning it cannot make or replicate changes to the domain. By default, it does not store user passwords, reducing risk if the server is compromised.