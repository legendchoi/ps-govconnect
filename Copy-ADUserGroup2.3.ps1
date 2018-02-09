# version 2.4
Param(
    [Parameter(Mandatory=$false)][string]$src_user,
    [Parameter(Mandatory=$false)][string]$dst_user
)

."$PSScriptRoot\includes\functions.ps1"
."$PSScriptRoot\includes\Letter-Service.ps1"

Function Compare-GroupMembership {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)][String]$ReferenceUser,
        [Parameter(Mandatory=$True)][String]$DeferenceUser, # Spelling
        [Parameter(Mandatory=$True)][String]$Comparison,
        [Parameter()][bool]$ShortName = $false
    )
    $ReferenceGroups = (Get-ADUser -Identity $ReferenceUser -Properties MemberOf).MemberOf | Sort-Object
    $DeferenceGroups = (Get-ADUser -Identity $DeferenceUser -Properties MemberOf).MemberOf | Sort-Object
    
    if ($DeferenceGroups -eq $null) {
        if($Comparison -eq "<="){
            if ($ShortName) {
                $ReferenceGroups = $ReferenceGroups | ForEach-Object {([regex]::split($_,'^CN=|,.+$'))[1]}
            }
            return $ReferenceGroups
        } else {
            return "Null" # $null
        }
    } else {
        if ($ShortName) {
            return Compare-Object $ReferenceGroups $DeferenceGroups -IncludeEqual | Where-Object {$_.SideIndicator -eq $Comparison} | Select-Object -ExpandProperty InputObject | ForEach-Object {([regex]::split($_,'^CN=|,.+$'))[1]}
        } else {
            return Compare-Object $ReferenceGroups $DeferenceGroups -IncludeEqual | Where-Object {$_.SideIndicator -eq $Comparison} | Select-Object -ExpandProperty InputObject
        }
    }
}

Function Test-ADUserName {
    [CmdletBinding()]
    Param ([parameter(Mandatory=$false)][string]$Identity)
    do {
        $Identity = Read-Host "User Name"
        $Identity = $Identity.Trim()
        try {
            $UserFullName = Get-ADUser -Identity $Identity -Properties DisplayName -ErrorAction Stop | select-object -expandproperty DisplayName
        } catch {
            Write-Host "No such user found! Check it again, Dude!" -ForegroundColor Red
        }
    } while (!$UserFullName)
    return $UserFullName
}

Function Get-ADUserName {
    [CmdletBinding()]
    Param ([parameter(Mandatory=$true)][string]$Identity)

    $Identity = $Identity.Trim()
    try {
        $DisplayName = (Get-ADUser -Identity $Identity -Properties DisplayName).DisplayName
    } catch {
        Write-Host "No such user found! Check it again, Dude!" -ForegroundColor Red
    }
    return $DisplayName
}

Function Filter-GroupMembership {
    [CmdletBinding()]
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
    [CmdletBinding()]
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
    [CmdletBinding()]
    Param ($TargetUserName,$RefUserName)
    $Header = "Dear Customer,"
    $Body = "`r`n`r`nThank you for contacting GovConnect Service Desk."
    $Body += "`r`nPlease be advised that requested additional group(s) have been added to $TargetUserName to allow access to/same as $RefUserName."
    $Body += "`r`nPlease restart the computer first to allow changes to take effect."
    $Footer = "`r`nRegards,`r`nGovConnect Service Desk`nPhone: 1800 217 640`r`nPortal: https://portal.govconnect.nsw.gov.au"
    return ($Header + $Body + $Footer)
}

Function Write-Note {
    [CmdletBinding()]
    Param ($TicketNumber)
    $Today = Get-Date -Format "dd-MMM-yyyy"
    return $Note = "Modified Access: $TicketNumber / $Today"
}

function Show-Greeting {
    Write-Host " Copying Group Memberships"
    Write-Host "---------------------------"
}

## Main process block 

# Filter out the security groups containing the keywords blow 
$Filter = "CTX|XenAPP|Administrator|Cisco|UAT Users|UAT - Users|OBJECTIVE USERS A|RDP|APP MS Office 2016 x86 ProPlus|APP MS Office 365|O365Licensing|lync|Office 356 Test Users"

do {
    Clear-Host
    Show-Greeting

    do {
        # $TryAgain = $false

        do{
            # Reference User
            Write-Host 'Enter the name of the account to read the groups ' -NoNewline
            Write-Host 'FROM - ' -ForegroundColor Green -NoNewline
            $src_user = Select-User $src_user
            $src_user_name = Get-ADUserName $src_user

            # Target User
            Write-Host "`nEnter the name of the account to set the groups " -NoNewline
            Write-Host 'TO - ' -ForegroundColor Green -NoNewline
            $dst_user = Select-User $dst_user
            $dst_user_name = Get-ADUserName $dst_user

            # Check if the target user equal to the reference user
            if ($src_user -eq $dst_user) {
                Write-Warning "Excuse me, provided the source and destination user are the same! Please, try again!!!"
                $IsSame = $true
                $src_user = $null
                $dst_user = $null
            } else {
                $IsSame = $false
            }
        } while ($IsSame)

        # Summary and confirm
        Write-Host "`n---------------------------------------------------"
        Write-Host "Copying security groups"
        Write-Host -NoNewLine "From: "
        Write-Host "$src_user_name" -ForegroundColor Yellow
        Write-Host -NoNewLine "To  : "
        Write-HOst "$dst_user_name" -ForegroundColor Yellow
        Write-Host "---------------------------------------------------"
        $TryAgain = Read-Host "Continue[Enter] or press [X] to start again"

        if ($TryAgain -ieq 'x') {
            $TryAgain = $true
            $src_user = $null
            $dst_user = $null
        } else {
            $TryAgain = $false
        }

    } while ($TryAgain)

    $DifferentGroups = Compare-GroupMembership -ReferenceUser $src_user -DeferenceUser $dst_user -Comparison "<="
    # $DifferentGroups | ForEach-Object {([regex]::split($_,'^CN=|,.+$'))[1]}
        
    Write-Host "`n[Overview] " -NoNewline
    Write-Host "Note: The groups in red will not be copied" -ForegroundColor Magenta
    ## Groups to be excluded ##" -ForegroundColor DarkRed
    Filter-GroupMembership -Groups $DifferentGroups -Filter $Filter -Switch "In" | ForEach-Object {Write-Host (([regex]::split($_,'^CN=|,.+$'))[1]) -ForegroundColor DarkRed}
    ## Groups to be copied ##" -ForegroundColor DarkGreen
    $GroupsToCopy = Filter-GroupMembership -Groups $DifferentGroups -Filter $Filter -Switch "Ex"
    $GroupsToCopy | ForEach-Object {Write-Host -ForegroundColor DarkGreen (([regex]::split($_,'^CN=|,.+$'))[1])}

    # $GroupsToCopy
    if ($GroupsToCopy.count -eq 0) {
        Write-Host "`nNo groups to copy to the target user!!" -ForegroundColor Red
        $ConfirmCopy = $false
    } else {
        Write-Host -NoNewline "`nProceed to copy? " -ForegroundColor Yellow
        $ConfirmCopy = Read-Host "(Y/n)"
    }
        
    if ($ConfirmCopy -ieq 'y') {
        ## $group = Get-ADUser -Identity $src_user -Properties memberof | Select-Object -ExpandProperty memberof
        # Group Copy
        Write-Host "Copying groups ...`n"
        foreach ($member in $GroupsToCopy) {
            try { 
                Add-ADGroupMember -Identity $member -Members $dst_user -ea Stop
                $group = $member | ForEach-Object {([regex]::split($_,'^CN=|,.+$'))[1]}
                Write-Host -NoNewline $group
                Write-Host " - copied successfully" -ForegroundColor Green
            } catch {
                $memberError = $member | ForEach-Object {([regex]::split($_,'^CN=|,.+$'))[1]}
                Write-Host "$memberError - " -NoNewline -ForegroundColor Red
                Write-Warning $_
            }
        }
        Write-Host "`nCompleted!`n" -ForegroundColor Green
            
        # Writing Note
        # $ConfirmNote = Read-Host "Write a note? (y/n)"
        $ConfirmNote = 'y'
        if ($ConfirmNote -ieq "y") {
            $TicketNumber = Read-Host "Ticket Number"
            $Note = Write-Note -TicketNumber $TicketNumber
            Write-Host $Note
            $Info = Get-ADUser $dst_user -Properties info | %{ $_.info}
            try {
                Set-ADUser $dst_user -Replace @{info="$($Info) `r`n $Note"} -ErrorAction Stop
                Write-Host "Note Added" -ForegroundColor Green
            } catch {
                Write-Error $_
            }            
        }

        # Printing Letter
        # $ConfirmLetter = Read-Host "Print a letter? (y/n)"
        $ConfirmLetter = 'y'
        if ($ConfirmLetter -ieq 'y') {
            # $Letter = Write-NAPCLetter -TargetUserName $dst_user_name -RefUserName $src_user_name 
            $Letter = Write-NAPCLetter -TargetUser $dst_user -RefUser $src_user 
            $Letter | Out-File "Letter.txt"
            notepad.exe "Letter.txt"
            Write-Host "Letter printed" -ForegroundColor Green
        }
    }

    Write-Host "End of task" -ForegroundColor Yellow

    Write-Host "Do you wish to copy the " -NoNewline
    Write-Host "ABOVE " -ForegroundColor Yellow -NoNewline
    Write-Host "security groups to another user" -NoNewline
    $ChangeTarget = Read-Host "(y/n)?"
    if ($ChangeTarget -ieq 'y') {
        $continue = 'y'
        $dst_user = $null

    } else {
        $continue = Read-Host "`nDo you wish to add another set of security groups to another user (y/n)"
        if ($continue -ieq 'y') {
            $src_user = $null
            $dst_user = $null
        }
    }
    
} while ($continue -ieq 'y')

Write-Host "`nGood Bye! ^__^`n"
