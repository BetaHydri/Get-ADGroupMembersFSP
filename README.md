# Get-ADGroupMembersFSP

### DESCRIPTION:
    Gets the group membership and its Foreign Security Pricipals and translate them to a NTAccount.
    
#### SAMPLE1:
    .\Get-ADGroupMembersFSP -GroupName "Domain Admins"

#### SAMPLE2:
    .\Get-ADGroupMembersFSP -GroupName "MY Group" -Recursive

#### SAMPLE3:
    .\Get-ADGroupMembersFSP -GroupName "MY Group" -DomainName corp.contoso.com -Recursive

#### SAMPLE3:
    .\Get-ADGroupMembersFSP -GroupName "MY Group" -DomainName corp.contoso.com -Recursive

#### SAMPLE4:
    .\Get-ADGroupMembersFSP -GroupName "MY Group" -DomainName corp.contoso.com -UserName corp\myuser -Recursive

    
OUTPUT:
|DistinguishedName                                              | ObjectClass | NTAccount
|---------------------------------------------------------------|-------------|--------------------------
|CN=IT-DA,OU=UserAccounts,DC=corp,DC=contoso,DC=com             | group       | CONTOSO\IT-DA
|CN=wwioadministrator,OU=UserAccounts,DC=corp,DC=contoso,DC=com | user        | CONTOSO\wwioadministrator
