# NFS (port 111,2049)
Network File System (NFS) is a network file system developed by Sun Microsystems and has the same purpose as SMB. Its purpose is to access file systems over a network as if they were local. NFS is used between Linux and Unix systems.

The `/etc/exports` file contains a table of physical filesystems on an NFS server accessible by the clients. The default `exports` file also contains some examples of configuring NFS shares. First, the folder is specified and made available to others, and then the rights they will have on this NFS share are connected to a host or a subnet. Finally, additional options can be added to the hosts or subnets.

|Option|Description|Dangerous|
|-|-|-|
|`rw`|Read and write permissions.|💀|
|`ro`|Read only permissions.|
|`sync`|Synchronous data transfer. (A bit slower)|
|`async`|Asynchronous data transfer. (A bit faster)|
|`secure`|Ports above 1024 will not be used.|
|`insecure`|Ports above 1024 will be used.|💀|
|`no_subtree_check`|This option disables the checking of subdirectory trees.|
|`root_squash`|Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents root from accessing files on an NFS mount.|
|`no_root_squash`|All files created by root are kept with the UID/GID 0.|💀|
|`nohide`|If another file system was mounted below an exported directory, this directory is exported by its own exports entry.|💀|

## Show available NFS Shares
```
$ showmount -e <ip>
```
## Mounting NFS Share
```
$ mkdir target-NFS
$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
$ cd target-NFS
$ tree .

.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files
```
## List Contents with Uernames & Group Names
```
$ ls -l target-NFS/mnt/nfs/
```
## List Contents with UIDs & GUIDs
```
$ ls -n target-NFS/mnt/nfs/
```
It is important to note that if the root_squash option is set, we cannot edit the `backup.sh` file even as root. 

We can also use NFS for further escalation. For example, if we have access to the system via SSH and want to read files from another folder that a specific user can read, we would need to upload a shell to the NFS share that has the SUID of that user and then run the shell via the SSH user.

## Unmounting
```
sudo umount ./target-NFS
```

# Questions
1. Enumerate the NFS service and submit the contents of the flag.txt in the "nfs" share as the answer. **Answer: HTB{hjglmvtkjhlkfuhgi734zthrie7rjmdze}**
   - `$ showmount -e <ip>` -> get the path: `/var/nfs`
   - `$ mkdir target-NFS1`
   - `$ sudo mount -t nfs <ip>:/var/nfs ./target-NFS1 -o nolock`
   - `$ cat ./target-NFS1/flag.txt`
2. Enumerate the NFS service and submit the contents of the flag.txt in the "nfsshare" share as the answer. **Answer: HTB{8o7435zhtuih7fztdrzuhdhkfjcn7ghi4357ndcthzuc7rtfghu34}**
   - `$ showmount -e <ip>` -> get the path: `/mnt/nfsshare`
   - `$ mkdir target-NFS2`
   - `$ sudo mount -t nfs <ip>:/mnt/nfsshare ./target-NFS2 -o nolock`
   - `$ cat ./target-NFS2/flag.txt`