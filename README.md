# Get-ADGroupMembersFSP

### DESCRIPTION:
    ```
    Gets the group memberships of a AD Group in the actual DNS Computer AD Domain. When a  member is a Foreign Security Principal then translate them to a NTAccount. Furthermore if Recursion has been defined, then follow the nested membership of the Foreign Security Principal if this has been indentified as ObjectClass group. Credentials will be asked for every member that is a Foreign Security Principal in the trusted domain.
    ```
```powershell
SAMPLE1:
    #Get group members of Domain Admins" in the actual domain of client
    .\Get-ADGroupMembersFSP.ps1 -GroupName "Domain Admins"

SAMPLE2:
    #Get group members of "My Group" in the actual Domain of client recursively 
    .\Get-ADGroupMembersFSP.ps1 -GroupName "MY Group" -Recursive

```
    
OUTPUT as [PsCustomObject]:
|DistinguishedName                                                              | ObjectClass    | NTAccount
:-------------------------------------------------------------------------------|:---------------|:-------------------------------
CN=AutoDL System Account,OU=CoreIdentity,DC=redmond,DC=contoso,DC=com           | user           | REDMOND\adlsys    
CN=Exchange Domain Servers,CN=Users,DC=africa,DC=contoso,DC=com                 | group          | AFRICA\Exchange Domain Servers
CN=Exchange Domain Servers,CN=Users,DC=redmond,DC=contoso,DC=com                | group          | REDMOND\Exchange Domain Servers
CN=S-1-5-11\0ACNF:df5167ba-e8fb-4de2-958d-720652128486,CN=ForeignSecurityPrincipals,DC=europe,DC=contoso,DC=com | foreignSecurityPrincipal | NT AUTHORITY\Authenticated Users
CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=europe,DC=contoso,DC=com             | foreignSecurityPrincipal | Everyone
