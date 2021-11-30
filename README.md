# Get-ADGroupMembersFSP

### DESCRIPTION:
    Gets the group membership and its Foreign Security Pricipals and translate them to a NTAccount.
```   
SAMPLE1:
    Get group members of Domain Admins" in domain of server
    .\Get-ADGroupMembersFSP -GroupName "Domain Admins"

SAMPLE2:
    Get group members of "My Group" in Domain of server recursively 
    .\Get-ADGroupMembersFSP -GroupName "MY Group" -Recursive

SAMPLE3:
    Get group members of "My Group" in Domain corp.contoso.com recursively 
    .\Get-ADGroupMembersFSP -GroupName "MY Group" -DomainName corp.contoso.com -Recursive

SAMPLE4:
    Get group members of "My Group" recursively but authenticate as corp\myuser
    .\Get-ADGroupMembersFSP -GroupName "MY Group" -UserName corp\myuser -Recursive

SAMPLE5:
    Get group members of "My Group" in Domain corp.contoso.com recursively but authenticate as corp\myuser
    .\Get-ADGroupMembersFSP -GroupName "MY Group" -DomainName corp.contoso.com -UserName corp\myuser -Recursive
```
    
OUTPUT:
|DistinguishedName                                              | ObjectClass | NTAccount
|---------------------------------------------------------------|-------------|--------------------------
|CN=IT-DA,OU=UserAccounts,DC=corp,DC=contoso,DC=com             | group       | CONTOSO\IT-DA
|CN=wwioadministrator,OU=UserAccounts,DC=corp,DC=contoso,DC=com | user        | CONTOSO\wwioadministrator
