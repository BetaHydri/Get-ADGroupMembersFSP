<#
<#PSScriptInfo
 
.VERSION
1.0.0

.GUID
c05766cc-8031-45fe-a45f-cd1420c642ce

.AUTHOR
Jan Tiedemann

.COMPANYNAME
Microsoft

.COPYRIGHT 2021

.TAGS
ADGroup Groupmembers ActiveDirectory Groups Members FSP

.DESCRIPTION
Get the group membership an its Foreign Security Pricipals and translate them to a NTAccount.

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
#>

<#
 
.DESCRIPTION
Gets the group membership and its Foreign Security Pricipals and translate them to a NTAccount.
.INPUTS
An ActiveDirectory group name as string
.OUTPUTS
Returns a object with NoteProperties DistinguisehdName, ObjectClass, NTAccount
.PARAMETER GroupName
    Required. This parameter represents the name of the group to investigate.
.PARAMETER Recursive
    Optional. This parameter tells the function to do a recursive membership query of the given groupmembership.
.EXAMPLE
     Get-ADGroupMembersFSP.ps1 -GroupName "Domain Admins"
     This example will output an object with all direct memebers of the Domain Admins group with their DN, ObjectClass and NTAccount
.EXAMPLE
    Get-ADGroupMembersFSP.ps1 -GroupName "Domain Admins" -Recursive
    This example will output an object with all recursive memebers of the Domain Admins group with their DN, ObjectClass and NTAccount
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true,
        Position = 0,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Enter GroupName to get members")]
    [ValidateNotNullOrEmpty()]
    [String]$GroupName,
    [Parameter(Mandatory = $false,
        Position = 1,
        HelpMessage = "Enter GroupName to get members from")]
    [Switch]$Recursive = $false
)

#region HelperFuntions
function Get-Trusts {
    [CmdletBinding()]  
    param (
        $Domain,
        [pscredential]$Credential
    )
    $trustInfo = @()
    $trustlist = Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' `
        -Server $Domain `
        -Properties securityIdentifier, Name, TrustDirection
    foreach ($trust in $trustlist) {
        if ($trust.TrustDirection -eq 2 -or $trust.TrustDirection -eq 3) {
            $htTrust = @{ }
            $htTrust.Name = $trust.Name
            $htTrust.SID = $trust.securityIdentifier.ToString()
            $objTrust = New-Object psobject -Property $htTrust
            $trustInfo += $objTrust
        }
    }
    return $trustInfo
}
function Get-DomainFromDN {
    [CmdletBinding()]
    param (
        $DN
    )
    $domain = $DN -Split "," | Where-Object { $_ -like "DC=*" }
    $domain = $domain -join "." -replace ("DC=", "")
    return $domain
}  
function Get-AllMembersFromGroup {
    [CmdletBinding()]
    param (
        $GroupName,
        $DomainName
    )
    begin {
        $memberlist = @()
        $ObjectInfo = @()
    }
    process {
        try {
            $memberlist = ((Get-ADGroup -Identity $GroupName -Server $DomainName -Properties Members).Members) 
            foreach ($memberDN in $memberlist) {
                # From UserDN make Domain FQDN
                $domain = Get-DomainFromDN -DN $memberDN
                # Check if DN Object is a group or other type
                $AdObject = (Get-ADObject $memberDN -Server $domain -Properties DistinguishedName, ObjectClass, Name)
                $ObjectList = [PSCustomObject]@{
                    DistinguishedName = $memberDN
                    ObjectClass       = $AdObject.ObjectClass
                }
                If ($AdObject.objectClass -eq "group") {
                    do {
                        $ObjectInfo += $ObjectList
                        Write-Debug "Group: $AdObject.DistinguishedName"
                        Get-AllMembersFromGroup -GroupName $AdObject.DistinguishedName -DomainName $domain
                    } while (-Not($ObjectList.DistinguishedName.Contains($AdObject.DistinguishedName)))                
                }
                Elseif ($AdObject.objectClass -eq "user") {
                    do {
                        $ObjectInfo += $ObjectList
                        Write-Debug "User: $AdObject.DistinguishedName"
                    } while (-Not($ObjectList.DistinguishedName.Contains($AdObject.DistinguishedName)))
                }
                Else {
                    do {
                        $ObjectInfo += $ObjectList
                        Write-Debug "Others: $AdObject.DistinguishedName"
                    } while (-Not($ObjectList.DistinguishedName.Contains($AdObject.DistinguishedName)))                    
                }
                
            }
        }
        catch {
            Write-Debug "$Error[0].Exception.InnerException.Message"
        }
    }
    end {
        Return ($ObjectInfo)
    }
}
function Get-MyMembers {
    [CmdletBinding()]
    param (
        $GroupName,
        $DomainName = (Get-ADDomain).DNSRoot,
        [switch]$Recursive = $false
    )
    switch ($Recursive) {
        $false { 
            $ObjectInfo = @()
            try {
                $myMemberList = (Get-ADGroup $GroupName -Properties Members).Members
                foreach ($memberDN in $myMemberList) {
                    # From UserDN make Domain FQDN
                    $domain = Get-DomainFromDN -DN $memberDN
                    # Check if DN Object is a group or other type
                    $AdObject = (Get-ADObject $memberDN -Server $domain -Properties DistinguishedName, ObjectClass, Name)
                    $ObjectList = [PSCustomObject][ordered]@{
                        DistinguishedName = $memberDN
                        ObjectClass       = $AdObject.ObjectClass
                    }
                    $ObjectInfo += $ObjectList
                }
                return $ObjectInfo
            }
            catch {
                Write-Debug "$Error[0].Exception.InnerException.Message"
            }
        }
        $true {
            $membersrecursive = @()
            try {
                $membersrecursive = Get-AllMembersFromGroup -GroupName $GroupName -DomainName $DomainName
            }
            catch {
                Write-Debug "$Error[0].Exception.InnerException.Message"
            }
            return $membersrecursive 
        }
    }
    
}
function Resolve-FSPs {
    [CmdletBinding()]
    param (
        $GroupMembers
    )
    $newList = @()
    foreach ($member in $GroupMembers) {
        if ($member -like "*ForeignSecurityPrincipals*" ) {
            # Extract SID from foreign security principal DN
            $FSPSID = $member.substring($member.indexof("=") + 1, $($member.indexof(",") - 3))
            try {
                # Translate FSBSid to NTAccount (aka Domain\user)
                $SID = New-Object System.Security.Principal.SecurityIdentifier($FSPSID)
                $Resolved = $SID.Translate([System.Security.Principal.NTAccount])
                $newList += $Resolved.Value
            }
            catch {
                # If SID can't be translated add at least FSB DN to new array
                $newList += $member
            }
        }
        else {
            # From UserDN make Domain FQDN
            $domain = Get-DomainFromDN -DN $member
            # Get domain\user (aka msDS-PrincipalName) from ADUser DN
            $principalName = (Get-ADObject $member -Server $domain -Properties msDS-PrincipalName)."msDS-PrincipalName" 
            $newList += $principalName
        }
    }
    Return $newList
}
#endregion

#region main
try {
    Import-Module ActiveDirectory
}
Catch {
    Write-Host "ActiveDirectory Module needed"
    break
}
$memberDNs = @()
$membersNTAccounts = @()
Clear-Host
switch ($Recursive) {
    false {
        $memberDNs = Get-MyMembers -GroupName $GroupName -DomainName ($(Get-ADDomain).DNSRoot)
        $membersNTAccounts = Resolve-FSPs -GroupMembers ($memberDNs).DistinguishedName
        for ($i = 0; $i -lt $membersNTAccounts.Count; $i++) {
            $memberDNs.Item($i) | Add-Member -MemberType NoteProperty -Name 'NTAccount' -Value ($($membersNTAccounts.Item($i)))
        }

    }
    true {
        $memberDNs = Get-MyMembers -GroupName $GroupName -DomainName ($(Get-ADDomain).DNSRoot) -Recursive
        $membersNTAccounts = Resolve-FSPs -GroupMembers ($memberDNs).DistinguishedName
        for ($i = 0; $i -lt $membersNTAccounts.Count; $i++) {
            $memberDNs.Item($i) | Add-Member -MemberType NoteProperty -Name 'NTAccount' -Value ($($membersNTAccounts.Item($i)))
        }
    }
}
$memberDNs
#endregion