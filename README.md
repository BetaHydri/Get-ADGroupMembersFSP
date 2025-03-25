# Get-ADGroupMembersFSP

### DESCRIPTION:
```
Gets the group memberships of an AD Group in the actual DNS computers AD Domain. 
When a member of the provided group is from ObejctClass ForeignSecurityPrincipal then translate
it to a NTAccount. Furthermore if Recursion switch has been defined, then follow the nested
memberships of the ForeignSecurityPrincipal, if this Object has been indentified as ObjectClass group. Credentials will be asked for every member that is a
ForeignSecurityPrincipal in the trusted domain.
```
```powershell
SAMPLE1:
    #Get group members of Domain Admins" in the actual domain of client
    .\Get-ADGroupMembersFSP.ps1 -GroupName "Domain Admins"

SAMPLE2:
    #Get group members of "My Group" in the actual Domain of client recursively 
    .\Get-ADGroupMembersFSP.ps1 -GroupName "MY Group" -Recursive

SAMPLE3:
    #Get group members of "My Group" in the actual Domain of client and export to CSV
    .\Get-ADGroupMembersFSP.ps1 -GroupName "MY Group" -OutputCsvFile "C:\path\to\output.csv"

SAMPLE4:
    #Get group members of "My Group" in the actual Domain of client and export to CSV with custom delimiter
    .\Get-ADGroupMembersFSP.ps1 -GroupName "MY Group" -OutputCsvFile "C:\path\to\output.csv" -CsvDelimiter ";"
```

OUTPUT as [PsCustomObject]:
|DistinguishedName                                                              | ObjectClass    | NTAccount | Occurrences
:-------------------------------------------------------------------------------|:---------------|:-------------------------------|:-----------
CN=CN=S-1-5-21-190482134-350692921-3341096118-1108,CN=ForeignSecurityPrincipals,DC=mylabs,DC=contoso,DC=com           | foreignSecurityPrincipal           | LABSFAB\APP01-Fabrikam-Group    | 1
CN=Markus Helf,OU=Users,OU=LABSFAB,DC=labsfab,DC=fabrikam,DC=com                 | user          | LABSFAB\markus | 2
CN=Administrator,CN=Users,DC=labsfab,DC=fabrikam,DC=com                | user          | LABSFAB\Administrator | 1
CN=Test01,OU=Groups,OU=LABSFAB,DC=labsfab,DC=fabrikam,DC=com | group | LABSFAB\Test01 | 1
CN=Tim Hoff,OU=Users,OU=LABSFAB,DC=labsfab,DC=fabrikam,DC=com             | user | LABSFAB\Tim | 1

### ADDITIONAL OUTPUT:
Initial Group Name: [GroupName]
Total Members: [Total Members Count]
Total Unique Members: [Total Unique Members Count]
