# Active Directory Groups
One question that comes up often is the difference between Groups and Organizational Units (OUs). As discussed earlier in the module, OUs are useful for grouping users, groups, and computers to ease management and deploying Group Policy settings to specific objects in the domain. Groups are primarily used to assign permissions to access resources. OUs can also be used to delegate administrative tasks to a user, such as resetting passwords or unlocking user accounts without giving them additional admin rights that they may inherit through group membership.

```
🧠 Simple Analogy

OU = Classroom (where students are organized and rules are applied)

Group = Permission list (who is allowed to enter the lab or use equipment)
```

## Types of Groups
In simpler terms, groups are used to place users, computers, and contact objects into management units that provide ease of administration over permissions and facilitate the assignment of resources such as printers and file share access. 

Groups in Active Directory have two fundamental characteristics: `type` and `scope`. The `group type` defines the group's purpose, while the `group scope` shows how the group can be used within the domain or forest. When creating a new group, we must select a group type. There are two main types: `security` and `distribution` groups.

### Group Type And Scope
The `Security groups` type is primarily for ease of assigning permissions and rights to a collection of users instead of one at a time. All users added to a security group will inherit any permissions assigned to the group, making it easier to move users in and out of groups while leaving the group's permissions unchanged.

The `Distribution groups` type is used by email applications such as Microsoft Exchange to distribute messages to group members. They function much like mailing lists and allow for auto-adding emails in the "To" field when creating an email in Microsoft Outlook. This type of group cannot be used to assign permissions to resources in a domain environment.

## Group Scopes
There are three different `group scopes` that can be assigned when creating a new group.

### Domain Local Group
Domain local groups can only be used to manage permissions to domain resources in the domain where it was created. Local groups cannot be used in other domains but CAN contain users from OTHER domains. Local groups can be nested into (contained within) other local groups but NOT within global groups.

### Global Group
Global groups can be used to grant access to resources in another domain. A global group can only contain accounts from the domain where it was created. Global groups can be added to both other global groups and local groups.

### Universal Group
The universal group scope can be used to manage resources distributed across multiple domains and can be given permissions to any object within the same forest. They are available to all domains within an organization and can contain users from any domain. Unlike domain local and global groups, universal groups are stored in the Global Catalog (GC), and adding or removing objects from a universal group triggers forest-wide replication. Replication is only triggered at the individual domain level when a user is removed from a global group.

### AD Group Scope Examples

```pwsh
PS C:\htb> Get-ADGroup  -Filter * |select samaccountname,groupscope

samaccountname                           groupscope
--------------                           ----------
Administrators                          DomainLocal
Users                                   DomainLocal
Guests                                  DomainLocal
Print Operators                         DomainLocal
Backup Operators                        DomainLocal
Replicator                              DomainLocal
Remote Desktop Users                    DomainLocal
Network Configuration Operators         DomainLocal
Distributed COM Users                   DomainLocal
IIS_IUSRS                               DomainLocal
Cryptographic Operators                 DomainLocal
Event Log Readers                       DomainLocal
Certificate Service DCOM Access         DomainLocal
RDS Remote Access Servers               DomainLocal
RDS Endpoint Servers                    DomainLocal
RDS Management Servers                  DomainLocal
Hyper-V Administrators                  DomainLocal
Access Control Assistance Operators     DomainLocal
Remote Management Users                 DomainLocal
Storage Replica Administrators          DomainLocal
Domain Computers                             Global
Domain Controllers                           Global
Schema Admins                             Universal
Enterprise Admins                         Universal
Cert Publishers                         DomainLocal
Domain Admins                                Global
Domain Users                                 Global
Domain Guests                                Global

<SNIP>
```

Group scopes can be changed, but there are a few caveats:

- A Global Group can only be converted to a Universal Group if it is NOT part of another Global Group.
- A Domain Local Group can only be converted to a Universal Group if the Domain Local Group does NOT contain any other Domain Local Groups as members.
- A Universal Group can be converted to a Domain Local Group without any restrictions.
- A Universal Group can only be converted to a Global Group if it does NOT contain any other Universal Groups as members.

## Built-in vs. Custom Groups
Several built-in security groups are created with a Domain Local Group scope when a domain is created. It is important to note that only user accounts can be added to these built-in groups as they do not allow for group nesting (groups within groups). Some examples of built-in groups included `Domain Admins`, which is a `Global` security group and can only contain accounts from its own domain. If an organization wants to allow an account from domain B to perform administrative functions on a domain controller in domain A, the account would have to be added to the built-in Administrators group, which is a `Domain Local` group.

## Nested Group Membership
Through this membership, a user may inherit privileges not assigned directly to their account or even the group they are directly a member of, but rather the group that their group is a member of. This can sometimes lead to unintended privileges granted to a user that are difficult to uncover without an in-depth assessment of the domain. Tools such as [BloodHound](https://github.com/BloodHoundAD/BloodHound) are particularly useful in uncovering privileges that a user may inherit through one or more nestings of groups.

## Important Group Attributes
Some of the most important group attributes include:

- `cn`: The cn or Common-Name is the name of the group in Active Directory Domain Services.
- `member`: Which user, group, and contact objects are members of the group.
- `groupType`: An integer that specifies the group type and scope.
- `memberOf`: A listing of any groups that contain the group as a member (nested group membership).
- `objectSid`: This is the security identifier or SID of the group, which is the unique value used to identify the group as a security principal.

## Questions
1. What group type is best utilized for assigning permissions and right to users? **Answer: Security**
2. True or False; A "Global Group" can only contain accounts from the domain where it was created. **Answer: True**
3. Can a Universal group be converted to a Domain Local group? (yes or no) **Answer: Yes**