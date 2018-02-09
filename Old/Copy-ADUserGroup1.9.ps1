<#
.SYNOPSIS   
	Script that compares group membership of source user to destination user, copy/changes destination user group membership
    
.DESCRIPTION 
	This script compares the group membership of $SourceAccount and $DestinationAccount, based on the membership of the
	source account the destination account is also added to these groups. Script outputs actions taken to the prompt.
	The script can also run without any parameters then the script will prompt for both usernames. The GUI is intended
	to simplify this process and to give a better overview of the action the script intends to perform.
 
.PARAMETER SourceAccount
    User of which group membership is read

.PARAMETER DestinationAccount
    User of which group membership will be changed by comparing it to source user

.NOTES   
    Name: Copy-ADuserGroup.ps1
    Author: Hyun Choi
    DateCreated: 2017-05-1
    Version: 1.7
	Email: hyun.choi@au.unisys.com

.EXAMPLE   
	.\Copy-ADuserGroup.ps1 sourceuser destinationuser

Description 
-----------     
This command will copy from groups sourceuser to match groups that destinationuser is a member of the user is
prompted by user interface to confirm these changes.

.EXAMPLE   
	.\Copy-ADuserGroup.ps1

Description 
-----------     
Will use to prompt for confirmation
#>

Param(
    [Parameter()][string]$src_user,
    [Parameter()][string]$dst_user
)

$Filter = "CTX|XenAPP|Administrator|Mobility|Res_|Cisco|UAT Users|UAT - Users"

Function Get-ConnectExch {
	Param ([Parameter(Mandatory=$True)][string]$ConnectionUri)
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri
    Import-Module (Import-PSSession $Session -AllowClobber) -Global
}

Function Compare-GroupMembership { # Long name
    Param (
        [Parameter(Mandatory=$True)][String]$ReferenceUser,
        [Parameter(Mandatory=$True)][String]$DeferenceUser,
        [Parameter(Mandatory=$True)][String]$Comparison,
        [Parameter()][bool]$ShortName = $false
    )
    $ReferenceGroups = (Get-ADUser -Identity $ReferenceUser -Properties MemberOf).MemberOf | Sort-Object
    $DeferenceGroups = (Get-ADUser -Identity $DeferenceUser -Properties MemberOf).MemberOf | Sort-Object
    if ($ShortName) {
        return Compare-Object $ReferenceGroups $DeferenceGroups -IncludeEqual | Where-Object {$_.SideIndicator -eq $Comparison} | Select-Object -ExpandProperty InputObject | ForEach-Object {([regex]::split($_,'^CN=|,.+$'))[1]}
    } else {
        return Compare-Object $ReferenceGroups $DeferenceGroups -IncludeEqual | Where-Object {$_.SideIndicator -eq $Comparison} | Select-Object -ExpandProperty InputObject
    }
    
}

Function Compare-GroupMembership2 { # Short name
    Param (
        [Parameter(Mandatory=$True)][String]$ReferenceUser,
        [Parameter(Mandatory=$True)][String]$DeferenceUser,
        [Parameter(Mandatory=$True)][String]$Comparison
    )
    $ReferenceGroups = (Get-ADPrincipalGroupMembership $ReferenceUser).name | Sort-Object
    $DeferenceGroups = (Get-ADPrincipalGroupMembership $DeferenceUser).name | Sort-Object
    return Compare-Object $ReferenceGroups $DeferenceGroups -IncludeEqual | Where-Object {$_.SideIndicator -eq $Comparison} | Select-Object -ExpandProperty InputObject
}

Function Get-ADUserName {
    Param ([parameter(Mandatory=$True)][string]$ADUser)
    $ADUser = $ADUser.Trim()
	try {
		$UserFullName = Get-ADUser -Identity $ADUser -Properties DisplayName -ErrorAction Stop | select-object -expandproperty DisplayName
        return $UserFullName
	} catch {
		Write-Warning "No such user found! Check it again, Dude!"
        return $null
	}
}

Function Filter-GroupMembership {
    param (
        [string[]]$Groups,
		[string]$Filter,
        [string]$Switch #["In"clude | "Ex"clude]
    )
    $ExcludedGroups = $Groups -notmatch $Filter
    $IncludedGroups = $Groups -match $Filter

    if ($Switch -eq "In") {
        return $IncludedGroups
    } else { # "Ex"
        return $ExcludedGroups
    }
}

Function Set-ADGroupMembership {
    param (
        [string[]]$Groups,
        [string]$ADUser
    )
    foreach ($Group in $Groups) {
        try {
            Add-ADGroupMember -Identity $Group -Members $ADUser -ErrorAction Stop
        } catch {
            $Group = [regex]::split($Group,'^CN=|,.+$')[1]
            Write-Warning "$Group - won't be added"
        }
    }
}

Function Write-Letter {
    Param ($TargetUserName,$RefUserName)
    $Header = "Dear Customer,"
    $Body = "`nThank you for contacting GovConnect Service Desk.`
    `nPlease be advised that requested additional group(s) have been added to $TargetUserName to allow access to/same as $RefUserName.`
    `nPlease restart the computer first to allow changes to take effect."
    $Footer = "`nRegards,`nGovConnect Service Desk`nPhone: 1800 217 640`nPortal: https://portal.govconnect.nsw.gov.au"
    return ($Header + $Body + $Footer)
}

Function Write-Note {
    Param ($TicketNumber)
    $Today = Get-Date -Format "dd-MMM-yyyy"
    return $Note = "Modified Access: $TicketNumber / $Today"
}

Do {
    # Clear-Host
    Write-Host "================================" -ForegroundColor Magenta
    Write-Host "    Copying Group Memberships   " -BackgroundColor Magenta
    Write-Host "================================" -ForegroundColor Magenta

    Do{
        # Source User Check
        Do {
            if (!$src_user) { $src_user = Read-Host 'Enter the name of the account to read the groups FROM' }
            $src_user_name = Get-ADUserName $src_user
            Write-Host "User Name: $src_user_name" -ForegroundColor DarkCyan
        } while ($src_user_name -eq $null)

        # Destination User Check
        Do {
            if (!$dst_user) { $dst_user = Read-Host 'Enter the name of the account to set the groups TO' }
            $dst_user_name = Get-ADUserName $dst_user
            Write-Host "User Name: $dst_user_name" -ForegroundColor DarkCyan
        } while ($dst_user_name -eq $null)

        if ($src_user -eq $dst_user) {
            Write-Warning "Excuse me, provided the source and destination user are the same! Please, try again!!!"
            $IsSame = $true
        } else {
            $IsSame = $false
        }
    } while ($IsSame)

    Write-host "`nThe script will copy the user groups from $src_user_name ===>>> $dst_user_name`n" -ForegroundColor Yellow

    Write-Host "[Groups in common]" -ForegroundColor Yellow
    Compare-GroupMembership -ReferenceUser $src_user -DeferenceUser $dst_user -Comparison "==" -ShortName $true

    Write-Host "`n[Different Groups ($dst_user_name only)]" -ForegroundColor Yellow
    Compare-GroupMembership -ReferenceUser $src_user -DeferenceUser $dst_user -Comparison "=>" -ShortName $true

    Write-Host "`n[Reference Groups ($src_user_name only)]" -ForegroundColor Yellow
    $DifferentGroups = Compare-GroupMembership -ReferenceUser $src_user -DeferenceUser $dst_user -Comparison "<=" # | foreach {([regex]::split($_,'^CN=|,.+$'))[1]}
    $DifferentGroups | ForEach-Object {([regex]::split($_,'^CN=|,.+$'))[1]}

    Write-Host "-Groups to be excluded" -ForegroundColor DarkYellow
    Filter-GroupMembership -Groups $DifferentGroups -Filter $Filter -Switch "In" | ForEach-Object {([regex]::split($_,'^CN=|,.+$'))[1]}

    Write-Host "-Groups to be copied" -ForegroundColor DarkYellow
    $GroupsToCopy = Filter-GroupMembership -Groups $DifferentGroups -Filter $Filter -Switch "Ex"
    $GroupsToCopy | ForEach-Object {([regex]::split($_,'^CN=|,.+$'))[1]}
    # $GroupsToCopy

    if ($GroupsToCopy.count -gt 1) {$isCopying = Read-Host "Do you want to proceed (Y/N)" }
    else {Write-Warning "Nothing to copy groups to the target user!!"}
    
    if ($isCopying -ieq 'y') {
        ## $group = Get-ADUser -Identity $src_user -Properties memberof | Select-Object -ExpandProperty memberof
        
        foreach ($member in $GroupsToCopy) {
            try { 
                Add-ADGroupMember -Identity $member -Members $dst_user -ea Stop
                $member | ForEach-Object {([regex]::split($_,'^CN=|,.+$'))[1]}
            } catch { Write-Warning $_ }
        }

        Write-Host "`nGroup copy completed!`n" -ForegroundColor Green

        $ConfirmLetter = Read-Host "Need Letter? (y/n)"

        if ($ConfirmLetter -ieq 'y') {
            $TicketNumber = Read-Host "Ticket Number"
            Write-Host "[Letter Body]" -ForegroundColor Yellow
            # Write-Host $PrivilegeChangeLetter
            Write-Letter -TargetUserName $dst_user_name -RefUserName $src_user_name
            Write-Host "[EOT]" -ForegroundColor Yellow

            # Note section
            Write-Host "`n[AD Note]" -ForegroundColor Yellow
            $Note = Write-Note -TicketNumber $TicketNumber
            Write-Host $Note

            $ConfirmNote = Read-Host "Appending a note in $dst_user_name's Telephone Tab? (y/n)"
            if ($ConfirmNote -ieq "y") {
                $Info = Get-ADUser $dst_user -Properties info | %{ $_.info}
                try {
                    Set-ADUser $dst_user -Replace @{info="$($Info) `r`n $Note"} -ErrorAction Stop
                    Write-Host "Note Added" -ForegroundColor Green
                } catch {
                    Write-Error $_
                }            
            }
        }
    }

    $continue = Read-Host "Do you want to continue? (y/n)"

} while ($continue -ieq 'y')

Write-Host "`nGood Bye! ^__^`n"