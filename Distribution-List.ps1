. "$PSScriptRoot\includes\Functions.ps1"

function Select-DL {
    [CmdletBinding()]
    param ($Identity)

    do {
        $repeat = $false
        if (!$Identity) {
            $DL = (Read-Host "Please provide a Distribution Group Name").Trim()
        } else {
            $DL = $Identity.Trim()
        }
        
        if($DL) {
            $DL = "*$DL*"
            $DLList = Get-ADGroup -Filter {GroupCategory -eq "Distribution" -and Name -like $DL} -Properties Name, SamAccountName, GroupScope, Mail

            if ($DLList.length -gt 1) {
                $Number = 1
                $DLList |
                    ForEach-Object {New-Object psObject -Property @{'Number'=$Number;'Name'=$_.Name;'SamAccountName'= $_.SamAccountName;'GroupScope'=$_.GroupScope;'Email' = $_.mail};$Number ++} |
                    Format-Table Number, Name, Email, SamAccountName, GroupScope -AutoSize | Out-Host

                do {
                    $repeatchoice = $false
                    $choice = Read-host "Please select the DL or [x] to try again"
                    if ($choice -match "[0-9]") {
                        $choice = [int]$choice
                        if ($choice -gt $DLList.length) {
                            write-host "too much number detected" -ForegroundColor Red
                            $repeatchoice = $true
                        } else { 
                            # right choice
                            $choice = $choice -1
                            $DL = $DLList[$choice].SamAccountName
                        }
                    } elseif ($choice -ieq 'x') {
                        $repeatchoice = $false
                        $repeat = $true
                        $Identity = $false
                    } else {
                        # Not integer
                        write-host "not number detected" -ForegroundColor Red
                        $repeatchoice = $true
                    }
                } while ($repeatchoice)
            } elseif ($DLList.length -eq 0) {
                Write-Host "No distribution group found" -ForegroundColor Red
                $repeat = $true
                $Identity = $null
            } else {
                $DL = $DLList.SamAccountName
            }
        } else {
            Write-Host "No distribution group provided. Please, provide" -ForegroundColor Red
            $repeat = $true
        }
    } while ($repeat)
    $DLDisplayname = Get-ADGroup $DL -Properties displayname | Select-Object -ExpandProperty displayname
    $ManagedBy = (Get-ADGroup $DL -Properties ManagedBy).ManagedBy | Get-ADUser -Properties DisplayName | select -ExpandProperty DisplayName
    $MailAddress = (Get-ADGroup $DL -Properties mail).mail
    write-Host "Group Name: " -NoNewline 
    write-host $DLDisplayname -ForegroundColor green
    Write-Host "Managed by: $ManagedBy"
    Write-Host "Email Addr: $MailAddress"
    return $DL
}

function Check-IfUserHasDL {
    param($Identity,$DistributionGroup)
    $UserDistributionGroups = (Get-ADUser $Identity -Properties memberof).memberof | % { [regex]::Split($_,"^CN=|,.+$")[1] } | ?{$_ -imatch "dl"}

    # return $null if not matched, return [string]$DistributionGroup if matched.
    return $match = $UserDistributionGroups -imatch $DistributionGroup
}

function Select-Users {
    param ([string[]]$Users,[string]$DistributionGroup,[string]$Flag)

    $NameList = @()
    # Write-Host "`nPlease provide a user followed by ENTER. " -NoNewline -ForegroundColor Yellow
    # Write-Host "[X]" -ForegroundColor Red -NoNewline
    # Write-Host " followed by ENTER when done" -ForegroundColor Yellow
    do {

        Write-Host "`nPlease provide a user followed by ENTER. " -NoNewline # -ForegroundColor Yellow
        Write-Host "[X]" -ForegroundColor Red -NoNewline
        Write-Host " followed by ENTER will stop selecting users" # -ForegroundColor Yellow
        $UserName = Select-User -Flag $Flag

        if ($UserName -ine $Flag) {
            # This part is still in testing and developing...
            $DLName = (Get-ADGroup $DistributionGroup).Name
            $DLCheck = Check-IfUserHasDL -Identity $UserName -DistributionGroup $DLName
            if($DLCheck -ieq $DLName) {

                Write-Host ""
                Write-Host "WARNING: The user already have $DLName" -ForegroundColor DarkRed
                $ConfirmAdd = Read-Host "Do you still want to select the user? (y/n)"
                if ($ConfirmAdd -ieq 'y') {

                    
                } else {
                    $UserName = $null
                }

            } else {

            }

            
            if ($UserName -ne $null) {

                if ($Users -notcontains $UserName) {
                    $Users += $UserName
                    $Count = $Users.length
                    $DisplayName = (Get-ADUser $UserName -Properties DisplayName).DisplayName
                    $NameList += "| "+$DisplayName
                    # Write-Host "`nThe number of users selected ($Count): $NameList" -ForegroundColor Cyan
                } else {
                    Write-Host "`nERROR: Hey bro, you already have selected the user. Please wake up!" -ForegroundColor Red
                    $UserName = $null
                }

                Write-Host "`nThe number of users selected ($Count): $NameList" -ForegroundColor DarkGreen


                # $Users += $UserName
                # $Count = $Users.length
                # $DisplayName = (Get-ADUser $UserName -Properties DisplayName).DisplayName
                # $NameList += "| "+$DisplayName
                # Write-Host "`nThe number of users selected ($Count): $NameList" -ForegroundColor Cyan
            }
            

            
        }
        
        <#
        do {
            $Multi = Read-Host "More users? (Y/n)"
            if ($Multi -ieq 'y') {    
                $AddMoreUser = $true
                $repeat = $false
            } elseif ($Multi -notmatch "y|n") {
                Write-Host "Wrong choice!" -ForegroundColor Red
                $repeat = $true
            } else {
                $AddMoreUser = $false
                $repeat = $false
            } # do
        } while ($repeat)
        #>

    } while ($UserName -ine $Flag)
    # } while ($AddMoreUser)
    return $Users
}

function Display-MainMenu {

    Write-Host "====================================="
    Write-Host "   Distribution Group Operation      "
    Write-Host "====================================="
    Write-Host " 1) Add user(s)"
    Write-Host " 2) Remove user(s)"
    Write-Host " 3) Exit"
    Write-Host "====================================="
    do {
        $Choice = Read-Host "Please select"
        $Repeat = $false

        if ($Choice -notmatch "1|2|3") {
            Write-Host "Wrong choice. Try again"
            $Repeat = $true
        }
    } while ($Repeat)
    return $Choice
}





# Main
do {
    Clear-Host
    $Choice = Display-MainMenu
    $cancelstart = $false

    if ($Choice -ne '3') {
        Switch ([int]$Choice) {
            1 {$Operation = "Add"}
            2 {$Operation = "Remove"}
        }

        Write-Host "`nCurrent operation selected: " -NoNewline
        Write-Host "$Operation`n" -ForegroundColor Green

        # Distribution Group
        $DLname = Select-DL

        # Users
        $Users = Select-Users -Flag "X" -DistributionGroup $DLname
        $Count = $Users.Count
        Write-Host "TEST: How many user selected $Count"

        if ($Users.Count -gt 0) {
            # Display summary
            Write-Host "`n--------------------------------------------"
            Write-Host "                [Summary]"
            Write-Host "--------------------------------------------"
            Write-Host " Operation: "
            Write-Host "  - $Operation" -ForegroundColor Green
            Write-Host "--------------------------------------------"
            Write-Host " Distribution group selected: "
            Write-Host "  - $DLname" -ForegroundColor Green
            Write-Host "--------------------------------------------"
            Write-Host " Users selected:"
            $Users | % {Write-Host "  - $_" -ForegroundColor Green}
            Write-Host "--------------------------------------------"
    
            do {
                $flag = $false
                $ConfirmCommit = Read-Host "Press [ENTER] to continue or [C] to cancel and start over again"

                if (!$ConfirmCommit) {
            
                    # Operations
                    if ($Choice -eq '1') {
                        foreach ($User in $Users) {
                            try {
                                Add-ADGroupMember -Identity $DLname -Members $User -ErrorAction Stop
                                Write-Host $User -ForegroundColor Yellow -NoNewline
                                Write-Host " has " -NoNewline
                                Write-Host $DLname -ForegroundColor Yellow -NoNewline
                                Write-Host "... Added" -ForegroundColor Green
                            } catch {
                                Write-Host "Adding $DLname to $User Failed" -ForegroundColor Red
                            }
                        }
                    } else {
                        foreach ($User in $Users) {
                            try {
                                Remove-ADGroupMember -Identity $DLname -Members $User -Confirm:$false
                                Write-Host $User -ForegroundColor Yellow -NoNewline
                                Write-Host " got " -NoNewline
                                Write-Host $DLname -ForegroundColor Yellow -NoNewline
                                Write-Host "... Removed" -ForegroundColor Green
                            } catch {
                                Write-Host "Removing $DLname from $User Failed" -ForegroundColor Red
                            }
                        }
                    }

            
                } else {
                    if ($ConfirmCommit -ieq 'c') {
                        # $flag = $true
                        $cancelstart = $true
                    } else {
                        Write-Warning "Invalid selection!"
                        $flag = $true
                    }
                }
            } while ($flag)
        
        } else {
            Write-Host "ERROR: No user selected" -ForegroundColor Red
            $ConfirmRetry = Read-Host "Try again? (y/n)"
            if ($ConfirmRetry -ieq 'y') {
                $cancelstart = $true
            } else {
                # $cancelstart = $false
            }
        
        }

    }

} while ($cancelstart)

Write-Host "Bye :)" -ForegroundColor Yellow