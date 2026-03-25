# AD Administration: Guided Lab Part I

![alt text](helping-out.png)

## Tasks:
### Task 1: Manage Users
Our first task of the day includes adding a few new-hire users into AD. We are just going to create them under the `"inlanefreight.local"` scope, drilling down into the `"Corp > Employees > HQ-NYC > IT"` folder structure for now. Once we create our other groups, we will move them into the new folders. You can utilize the Active Directory PowerShell module (New-ADUser), the Active Directory Users and Computers snap-in, or MMC to perform these actions.

#### Users to Add:

<table class="bg-neutral-800 text-primary w-full mb-6 rounded-lg"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">User</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Andromeda Cepheus</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Orion Starchaser</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Artemis Callisto</code></td></tr></tbody></table>

Each user should have the following attributes set, along with their name:

<table class="bg-neutral-800 text-primary w-full mb-6 rounded-lg"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">Attribute</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">full name</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">email (first-initial.lastname@inlanefreight.local) ( ex. j.smith@inlanefreight.local )</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">display name</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">User must change password at next logon</code></td></tr></tbody></table>

Once we have added our new hires, take a quick second and remove a few old user accounts found in an audit that are no longer required.

#### Users to Remove

<table class="bg-neutral-800 text-primary w-full mb-6 rounded-lg"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"><strong class="font-bold">User</strong></th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Mike O'Hare</code></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Paul Valencia</code></td></tr></tbody></table>

Lastly `Adam Masters` has submitted a trouble ticket over the phone saying his account is locked because he typed his password wrong too many times. The helpdesk has verified his identity and that his Cyber awareness training is up to date. The ticket requests that you unlock his user account and force him to change his password at the next login.

### Task 2: Manage Groups and Other Organizational Units
Next up for us is to create a new Security Group called `Security Analysts` and then add our new hires into the group. This group should also be nested in an OU named the same under the `IT` hive. The `New-ADOrganizationalUnit` PowerShell command should enable you to quickly add a new security group. We can also utilize the AD Users and Computers snap-in like in Task-1 to complete this task.

### Task 3: Manage Group Policy Objects
Next, we have been asked to duplicate the group policy `Logon Banner`, rename it `Security Analysts Control`, and modify it to work for the new Analysts OU. We will need to make the following changes to the Policy Object:

- we will be modifying the Password policy settings for users in this group and expressly allowing users to access PowerShell and CMD since their daily duties require it.
- For computer settings, we need to ensure the Logon Banner is applied and that removable media is blocked from access.

Once done, make sure the Group Policy is applied to the `Security Analysts` OU. This will require the use of the Group Policy Management snap-in found under `Tools` in the Server Manager window. For more of a challenge, the `Copy-GPO` cmdlet in PowerShell can also be utilized.

## Questions
RDP to **10.129.202.146** (ACADEMY-IAD-DC01), with user `htb-student_adm` and password `Academy_student_DA!`
### Task 1:
#### Add Users
- `$ xfreerdp /v:10.129.202.146 /u:htb-student_adm /p:Academy_student_DA!` → RDP to the domain-joined Windows server
- Vist Active Directory Users and Computers
- ![alt text](add-user1.png)
- ![alt text](add-user2.png)
- ![alt text](add-user3.png)
- ![alt text](add-user4.png)
- ![alt text](add-user5.png)

#### Remove Users
- Still on Active Directory Users and Computers
- ![alt text](del-user1.png)
- ![alt text](del-user2.png)
- ![alt text](del-user3.png)

#### Unlock Adam Masters user account and force him to change his password at the next login
- Find Adam Masters account using the above method
- ![alt text](unlock-1.png)
- ![alt text](unlock-2.png)

### Task 2:
#### Create A New OU Under I.T.
- Still on Active Directory Users and Computers
- ![alt text](new-ou1.png)
- ![alt text](new-ou2.png)

#### Creating A Security Group
- Still on Active Directory Users and Computers
- ![alt text](new-group1.png)
- ![alt text](new-group2.png)
-  

#### Add Users To A Security Group
- ![alt text](user-group1.png)
- ![alt text](user-group2.png)
- ![alt text](user-group3.png)

### Task 3:
#### Duplicate the Object via PowerShell

```pwsh
PS C:\htb> Copy-GPO -SourceName "Logon Banner" -TargetName "Security Analysts Control"
```

The command above will take `Logon Banner` GPO and copy it to a new object named `Security Analyst Control`. This object will have all the old attributes of the `Logon Banner` GPO, but it will not be applied to anything until we link it.

#### Link the New GPO to an OU

```pwsh
PS C:\htb> New-GPLink -Name "Security Analysts Control" -Target "ou=Security Analysts,ou=IT,OU=HQ-NYC,OU=Employees,OU=Corp,dc=INLANEFREIGHT,dc=LOCAL" -LinkEnabled Yes
```

#### User Configuration Group Policies
We will be modifying the policies affecting users access to the command prompt as well as their ability to use removeable media.

- ![alt text](edit-policy.png)
- ![alt text](storage-1.png)
- ![alt text](storage-2.png)
- ![alt text](storage-3.png)
- ![alt text](storage-4.png)
- ![alt text](cmd-1.png)
- ![alt text](cmd-2.png)
- ![alt text](cmd-3.png)
- ![alt text](cmd-4.png)

#### Computer Configuration Group Policies
We will be modifying the policies affecting the Logon Banner for the host, and setting a more restrictive password policy.

- We will be validating the "Logon Banner" settings first. We validate the setting in "Interactive Logon Message Text" and "Interactive Logon Message Title".
- Ensure the radial to define the policy setting is enabled and there is a Banner in the text box. If all appears good, hit OK.
- ![alt text](banner-1.png)
- Change to the Message Title policy setting and validate the radial is selected, and a title of "Computer Access Policy" has been defined.
- ![alt text](banner-2.png)
- Now, we will modify the settings for the Password Policies so that all policies are as below
- ![alt text](password-6.png)