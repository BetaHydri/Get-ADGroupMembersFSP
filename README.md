# Get-ADGroupMembersFSP

DESCRIPTION
    Gets the group membership and its Foreign Security Pricipals and translate them to a NTAccount.
    
SAMPLE
    .\Get-ADGroupMembersFSP -GroupeName "Domain Admins"
    
OUTPUT
|DistinguishedName                                                        | ObjectClass | NTAccount
|-------------------------------------------------------------------------|-------------|-------------------------
|CN=IT-DA,OU=UserAccounts,DC=europe,DC=corp,DC=contoso,DC=com             | group       | CONTOSO\IT-DA
|CN=wwioadministrator,OU=UserAccounts,DC=europe,DC=corp,DC=contoso,DC=com | user        | CONTOSO\wwioadministrator
