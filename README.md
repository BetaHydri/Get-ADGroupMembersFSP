# Get-ADGroupMembersFSP

### DESCRIPTION:
    Gets the group membership and its Foreign Security Pricipals and translate them to a NTAccount.
```   
SAMPLE1:
    Get group members of Domain Admins" in domain of server
    .\Get-ADGroupMembersFSP.ps1 -GroupName "Domain Admins"

SAMPLE2:
    Get group members of "My Group" in Domain of server recursively 
    .\Get-ADGroupMembersFSP.ps1 -GroupName "MY Group" -Recursive

SAMPLE3:
    Get group members of "My Group" in Domain corp.contoso.com recursively 
    .\Get-ADGroupMembersFSP.ps1 -GroupName "MY Group" -DomainName corp.contoso.com -Recursive

SAMPLE4:
    Get group members of "My Group" recursively but authenticate as corp\myuser
    .\Get-ADGroupMembersFSP.ps1 -GroupName "MY Group" -UserName corp\myuser -Recursive

SAMPLE5:
    Get group members of "My Group" in Domain corp.contoso.com recursively but authenticate as corp\myuser
    .\Get-ADGroupMembersFSP.ps1 -GroupName "MY Group" -DomainName corp.contoso.com -UserName corp\myuser -Recursive
```
    
OUTPUT as [PsCustomObject]:
|DistinguishedName                                                              | ObjectClass    | NTAccount
:-------------------------------------------------------------------------------|:---------------|:-------------------------------
CN=AutoDL System Account,OU=CoreIdentity,DC=redmond,DC=contoso,DC=com,DC=com    | user           | REDMOND\adlsys    
CN=Exchange Domain Servers,CN=Users,DC=africa,DC=contoso,DC=com,DC=com          | group          | AFRICA\Exchange Domain Servers
CN=Exchange Domain Servers,CN=Users,DC=redmond,DC=contoso,DC=com,DC=com         | group          | REDMOND\Exchange Domain Servers
CN=S-1-5-11\0ACNF:df5167ba-e8fb-4de2-958d-720652128486,CN=ForeignSecurityPrincipals,DC=europe,DC=contoso,DC=com,DC=com | foreignSecurityPrincipal | NT AUTHORITY\Authenticated Users
CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=europe,DC=contoso,DC=com,DC=com      | foreignSecurityPrincipal | Everyone
