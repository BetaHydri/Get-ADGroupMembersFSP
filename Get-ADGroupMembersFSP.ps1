<#
<#PSScriptInfo
.VERSION
1.0.7

.GUID
c05766cc-8031-45fe-a45f-cd1420c642ce

.AUTHOR
Jan Tiedemann

.COMPANYNAME
Microsoft

.COPYRIGHT November 2021

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
Displays the initial group name with its direct or all unique members within the group 
Returns a system array object with NoteProperties DistinguisehdName, ObjectClass, NTAccount
.PARAMETER GroupName
    Required. This parameter represents the name of the group to investigate.
.PARAMETER Recursive
    Optional. This parameter tells the function to do a recursive membership query.
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
        ValueFromPipelineByPropertyName = $false,
        HelpMessage = "Enter DomainFQDN from initial Group")]
    [ValidateNotNullOrEmpty()]
    [String]$DomainName = [System.Net.Dns]::GetHostEntry($env:computername).HostName.Split(".", 2)[1],    
    
    [Parameter(Mandatory = $false,
        Position = 2,
        HelpMessage = "Enter UserName to authenticate")]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName, 
    
    [Parameter(Mandatory = $false,
        Position = 3,
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
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Enter GroupName to get members")]
        [ValidateNotNullOrEmpty()]
        [String]$GroupName,
        
        [Parameter(Mandatory = $true,
            Position = 1,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Enter Active Directory Domain FQDN")]
        [ValidateNotNullOrEmpty()]
        [String]$DomainFQDN
    )
    begin {
        $MemberList = @()
        $ObjectInfo = @()
    }
    process {
        try {
            # Array of group members
            $MemberList = ((Get-ADGroup -Identity $GroupName -Server $DomainFQDN -Properties Members).Members) 
            foreach ($memberDN in $MemberList) {
                # From UserDN make Domain FQDN
                $DomainFromUserDN = Get-DomainFromDN -DN $memberDN
                # Check if DN Object is a group or other type
                $AdObject = (Get-ADObject $memberDN -Server $DomainFromUserDN -Properties DistinguishedName, ObjectClass, Name)
                $ObjectList = [PSCustomObject][ordered]@{
                    DistinguishedName = $memberDN
                    ObjectClass       = $AdObject.ObjectClass
                }
                If ($AdObject.objectClass -eq "group" -or $AdObject.objectClass -eq "foreignsecurityprincipal") {
                    do {
                        # Adds PsCustomObject to Array
                        $ObjectInfo += $ObjectList
                        Write-Debug "Group: $AdObject.DistinguishedName"
                        Get-AllMembersFromGroup -GroupName $AdObject.DistinguishedName -DomainFQDN $DomainFromUserDN
                    } while (-Not($ObjectList.DistinguishedName.Contains($AdObject.DistinguishedName)))                
                }
                Elseif ($AdObject.objectClass -eq "user") {
                    do {
                        # Adds PsCustomObject to Arra
                        $ObjectInfo += $ObjectList
                        Write-Debug "User: $AdObject.DistinguishedName"
                    } while (-Not($ObjectList.DistinguishedName.Contains($AdObject.DistinguishedName)))
                }
                Else {
                    do {
                        # Adds PsCustomObject to Arra
                        $ObjectInfo += $ObjectList
                        Write-Debug "Others: $AdObject.DistinguishedName"
                    } while (-Not($ObjectList.DistinguishedName.Contains($AdObject.DistinguishedName)))                    
                }
                
            }
        }
        catch {
            Write-Host $error[0].Exception.Message -ForegroundColor Red
        }
    }
    end {
        Return ([object[]]$ObjectInfo)
    }
}
function Get-MyMembers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Enter GroupName to get members")]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName,
        
        [Parameter(Mandatory = $true,
            Position = 1,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Enter DomainFQDN to get group members from")]
        [ValidateNotNullOrEmpty()]
        [string]$DomainFQDN,

        [Parameter(Mandatory = $false)]
        [PsCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$Recursive = $false
    )
    switch ($Recursive) {
        $false { 
            $ObjectInfo = @()
            try {
                If ($Credential -and $DomainFQDN) {
                    $myMemberList = (Get-ADGroup $GroupName -Credential $Credential -Server $DomainFQDN -Properties Members).Members
                }
                elseif ($Credential) {
                    $myMemberList = (Get-ADGroup $GroupName -Credential $Credential -Properties Members).Members
                }
                else {
                    $myMemberList = (Get-ADGroup $GroupName -Server $DomainFQDN -Properties Members).Members
                }
                foreach ($memberDN in $myMemberList) {
                    # From UserDN make Domain FQDN
                    $DomainFromUserDN = Get-DomainFromDN -DN $memberDN
                    # Check if DN Object is a group or other type
                    if ($Credential.IsPresent) {
                        $AdObject = (Get-ADObject $memberDN -Server $DomainFromUserDN -Credential $Credential -Properties DistinguishedName, ObjectClass, Name)
                    }
                    else {
                        $AdObject = (Get-ADObject $memberDN -Server $DomainFromUserDN -Properties DistinguishedName, ObjectClass, Name)
                    }
                    $ObjectList = [PSCustomObject][ordered]@{
                        DistinguishedName = $memberDN
                        ObjectClass       = $AdObject.ObjectClass
                    }
                    $ObjectInfo += $ObjectList
                }
                return $ObjectInfo
            }
            catch {
                Write-Host $error[0].Exception.Message -ForegroundColor Red
            }
        }
        $true {
            $ObjectInfo = @()
            try {
                $ObjectInfo = Get-AllMembersFromGroup -GroupName $GroupName -DomainFQDN $DomainFQDN
            }
            catch {
                Write-Host $error[0].Exception.Message -ForegroundColor Red
            }
            return $ObjectInfo 
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
        if ($member -like "*ForeignSecurityPrincipals*") {
            # Extract SID from foreign security principal DN
            if ($member -like "*ACNF:*") {
                # CNF stands for conflict, you should check your AD.
                $FSPSID = $member.substring($member.indexof("=") + 1, $($member.indexof("\") - 3))
            }
            else {
                $FSPSID = $member.substring($member.indexof("=") + 1, $($member.indexof(",") - 3))
            }
            try {
                # Translate FSBSid to NTAccount (aka Domain\user)
                $SID = New-Object System.Security.Principal.SecurityIdentifier($FSPSID)
                $Resolved = $SID.Translate([System.Security.Principal.NTAccount])
                $newList += $Resolved.Value
                Write-Debug "Resolved FSP-SID: $Resolved.Value"
                # Check if the resolved NTAccount is a group
                $resolvedDomain = Get-DomainFromDN -DN $member
                $resolvedGroupName = $Resolved.Value.Split("\")[1]
                $foreignDomainFQDN = Get-DomainFromDN -DN $member
                $resolvedGroup = Get-ADGroup -Identity $resolvedGroupName -Server $foreignDomainFQDN -Properties Members -ErrorAction SilentlyContinue
                if ($resolvedGroup) {
                    $nestedMembers = Get-AllMembersFromGroup -GroupName $resolvedGroupName -DomainFQDN $foreignDomainFQDN
                    $newList += $nestedMembers.NTAccount
                }
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Write-Debug "ADIdentityNotFoundException: $($_.Exception.Message)"
                # Handle the exception by adding a placeholder
                $newList += "Unresolved FSP-SID: $member"
            }
            catch {
                # If SID can't be translated add at least FSB DN to new array with a placeholder
                $newList += "Unresolved FSP-SID: $member"
                Write-Debug "Unresolved FSP-SID: $member"
                # Try to use the resolved NTAccount to connect to the trusted AD domain with the provided credentials
                if ($Credential) {
                    try {
                        $resolvedGroup = Get-ADGroup -Identity $resolvedGroupName -Server $foreignDomainFQDN -Credential $Credential -Properties Members -ErrorAction SilentlyContinue
                        if ($resolvedGroup) {
                            $nestedMembers = Get-AllMembersFromGroup -GroupName $resolvedGroupName -DomainFQDN $foreignDomainFQDN
                            $newList += $nestedMembers.NTAccount
                        }
                    }
                    catch {
                        Write-Debug "Failed to connect to trusted AD domain with provided credentials"
                    }
                }
                else {
                    # Prompt for credentials if not provided
                    $Credential = Get-Credential -Message "Enter credentials for trusted AD domain: $resolvedDomain"
                    try {
                        $resolvedGroup = Get-ADGroup -Identity $resolvedGroupName -Server $foreignDomainFQDN -Credential $Credential -Properties Members -ErrorAction SilentlyContinue
                        if ($resolvedGroup) {
                            $nestedMembers = Get-AllMembersFromGroup -GroupName $resolvedGroupName -DomainFQDN $foreignDomainFQDN
                            $newList += $nestedMembers.NTAccount
                        }
                    }
                    catch {
                        Write-Debug "Failed to connect to trusted AD domain with provided credentials"
                    }
                }
                # Use LDAP queries to connect to the foreign domain of the group members in the trusted domains
                $ldapConnection = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$foreignDomainFQDN", $Credential.UserName, $Credential.GetNetworkCredential().Password)
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($ldapConnection)
                $searcher.Filter = "(objectClass=group)"
                $searcher.PropertiesToLoad.Add("member") | Out-Null
                $result = $searcher.FindOne()
                if ($result) {
                    $nestedMembers = $result.Properties["member"]
                    foreach ($nestedMember in $nestedMembers) {
                        $newList += $nestedMember
                    }
                }
            }
            # Ensure NTAccount is always included in the output
            if (-not $newList.Contains($Resolved.Value)) {
                $newList += $Resolved.Value
            }
        }
        else {
            # From UserDN make Domain FQDN
            $domain = Get-DomainFromDN -DN $member
            # Get domain\user (aka msDS-PrincipalName) from ADUser DN
            $principalName = (Get-ADObject $member -Server $domain -Properties msDS-PrincipalName)."msDS-PrincipalName" 
            $newList += $principalName
            Write-Debug "Normal Account: $principalName"
        }
    }
    return $newList
}
#endregion

#region main
try {
    Import-Module ActiveDirectory
}
Catch {
    Write-Host "ActiveDirectory Module couldn't be loaded"
    break
}
$memberDNs = @()
$membersNTAccounts = @()
switch ($Recursive) {
    $false {
        if ($UserName) {
            Write-Debug "Credentials: $UserName"
            $memberDNs = Get-MyMembers -GroupName $GroupName -Credential $UserName -DomainFQDN $DomainName
            $membersNTAccounts = Resolve-FSPs -GroupMembers ($memberDNs).DistinguishedName           
        }
        else {
            $memberDNs = Get-MyMembers -GroupName $GroupName -DomainFQDN $DomainName
            $membersNTAccounts = Resolve-FSPs -GroupMembers ($memberDNs).DistinguishedName
        }
        # Merge the two Objects to one
        If (($memberDNs).count -eq $membersNTAccounts.Count) {
            for ($i = 0; $i -lt $membersNTAccounts.Count; $i++) {
                $memberDNs.Item($i) | Add-Member -MemberType NoteProperty -Name 'NTAccount' -Value ($($membersNTAccounts.Item($i)))
            }
        }
        else {
            Write-Debug "Mismatch in the number of elements between memberDNs and membersNTAccounts" 
            # Ensure NTAccount is always included in the output
            for ($i = 0; $i -lt $memberDNs.Count; $i++) {
                $ntAccount = if ($i -lt $membersNTAccounts.Count) { $membersNTAccounts.Item($i) } else { "Unresolved NTAccount" }
                $memberDNs.Item($i) | Add-Member -MemberType NoteProperty -Name 'NTAccount' -Value $ntAccount
            }
        }
    }
    $true {
        if ($UserName) {
            $memberDNs = Get-MyMembers -GroupName $GroupName -DomainFQDN $DomainName -Credential $UserName -Recursive
            $membersNTAccounts = Resolve-FSPs -GroupMembers ($memberDNs).DistinguishedName
        }
        else {
            $memberDNs = Get-MyMembers -GroupName $GroupName -DomainFQDN $DomainName -Recursive
            $membersNTAccounts = Resolve-FSPs -GroupMembers ($memberDNs).DistinguishedName            
        }
        # Merge the two Objects to one
        If (($memberDNs).count -eq $membersNTAccounts.Count) {
            for ($i = 0; $i -lt $membersNTAccounts.Count; $i++) {
                $memberDNs.Item($i) | Add-Member -MemberType NoteProperty -Name 'NTAccount' -Value ($($membersNTAccounts.Item($i)))
            }
        }
        else {
            Write-Debug "Mismatch in the number of elements between memberDNs and membersNTAccounts"
            # Ensure NTAccount is always included in the output
            for ($i = 0; $i -lt $memberDNs.Count; $i++) {
                $ntAccount = if ($i -lt $membersNTAccounts.Count) { $membersNTAccounts.Item($i) } else { "Unresolved NTAccount" }
                $memberDNs.Item($i) | Add-Member -MemberType NoteProperty -Name 'NTAccount' -Value $ntAccount
            }
        }
    }
}
if ($Recursive) {
    Write-Host ("All unique members of group: {0}, Count: {1}" -f (($DomainName.split(".", 2)[0].ToUpper() + "\" + $GroupName), ($memberDNs.NTAccount).count)) -ForegroundColor Green
}
else {
    Write-Host ("Direct members of group: {0}, Count: {1}" -f (($DomainName.split(".", 2)[0].ToUpper() + "\" + $GroupName), [int]($memberDNs.NTAccount).count)) -ForegroundColor Green
}
$memberDNs
#endregion