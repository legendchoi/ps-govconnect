<#
SharedEmail Version 2.0
.DESCRIPTION 
v2.0 - bug fix when removing full & send as when it is cancelled which previously indicated as granted. It now show 'cencelled'
v1.8 - use 'alias' for selecting emailbox
#>

function Show-MastheadLogo {
    Write-Host " _____            _____                             _   _   _  _____  _    _ " -ForegroundColor Red
    Write-Host "|  __ \          /  __ \                           | | | \ | |/  ___|| |  | |" -ForegroundColor Magenta
    Write-Host "| |  \/ _____   _| /  \/ ___  _ __  _ __   ___  ___| |_|  \| |\ '--. | |  | |" -ForegroundColor Yellow
    Write-Host "| | __ / _ \ \ / / |    / _ \| '_ \| '_ \ / _ \/ __| __| . ' | '--. \| |/\| |" -ForegroundColor Green
    Write-Host "| |_\ \ (_) \ V /| \__/\ (_) | | | | | | |  __/ (__| |_| |\  |/\__/ /\  /\  /" -ForegroundColor Blue
    Write-Host " \____/\___/ \_/  \____/\___/|_| |_|_| |_|\___|\___|\__\_| \_/\____/  \/  \/ " -ForegroundColor DarkCyan
    Write-Host "                                                                    - Unisys" -ForegroundColor Red
}

function Show-Bye {
    Write-Host " ____"
    Write-Host "/\  _'\                    "
    Write-Host "\ \ \L\ \  __  __     __   " -ForegroundColor Red
    Write-Host " \ \  _ <'/\ \/\ \  /'__'\ " -ForegroundColor Blue
    Write-Host "  \ \ \L\ \ \ \_\ \/\  __/ " -ForegroundColor Yellow
    Write-Host "   \ \____/\/'____ \ \____\" -ForegroundColor Magenta
    Write-Host "    \/___/  '/___/> \/____/" -ForegroundColor Green
    Write-Host "               /\___/      "
    Write-Host "               \/__/"
}


# Function to create Exchange PSSession 
Function Connect-Exch {
	Param ([parameter()][string]$ConnectionUri = "http://dc1wexcamb01.govnet.nsw.gov.au/PowerShell/")
    
    if (!(Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" })) { 
        Write-Host "Connecting Exchange Server... `nPlease wait..." -ForegroundColor DarkGreen
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri
        Import-Module (Import-PSSession $session -AllowClobber) -Global
    } else {
        Write-Host "Existing Exch Session" -ForegroundColor DarkBlue
    }
}

function Set-FullAccess {
    param ($EmailboxName, $UserName)
    $Granted = $true
    Write-Host -NoNewline "Adding Full access: " -ForegroundColor DarkCyan
    try { 
        Add-MailboxPermission $EmailBoxName -User $UserName -AccessRights FullAccess -InheritanceType All -ErrorAction Stop -WarningAction Stop | Out-Null
        Write-Host "Full Access granted" -ForegroundColor Green
    } catch {
        Write-Host "Full Access grant failed" -ForegroundColor Red
        $Granted = $false
    }
    return $Granted
}

function Remove-FullAccess {
    param ($EmailboxName, $UserName)
    $Granted = $true
    Write-Host -NoNewline "Removing Full access: " -ForegroundColor DarkCyan
    try { 
        Remove-MailboxPermission $EmailBoxName -User $UserName -AccessRights FullAccess -InheritanceType All  -Confirm:$false -ErrorAction Stop -WarningAction Stop | Out-Null
        Write-host "Full Access removed" -ForegroundColor Green
    } catch {
        Write-Host "Full Access removal failed" -ForegroundColor Red
        # Write-Warning $_
        $Granted = $false 
    }
    return $Granted
}

function Set-SendAsAccess {
    param ($EmailboxName, $UserName)
    $Granted = $true
    Write-Host -NoNewline "Adding Send As access: " -ForegroundColor DarkCyan
    try { 
        
        Get-Mailbox $EmailboxName | Add-ADPermission -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop
        Write-Host "Send As granted" -ForegroundColor Green
    } catch { 
        $Granted = $false
        Write-Host "Send As grant failed" -ForegroundColor Red
        # Write-Error $_
        Write-Warning $_
    }
    return $Granted
}

function Remove-SendAsAccess {
    param ($EmailboxName, $UserName)
    $Granted = $true
    Write-Host -NoNewline "Removing Send As access: " -ForegroundColor DarkCyan
    try { 
        Get-Mailbox $EmailBoxName | Remove-ADPermission -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop -Confirm:$false
        Write-Host "Send As removed" -ForegroundColor Green
        <#
        $SendAsRemoved = Get-Mailbox $EmailBoxName | Remove-ADPermission -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop 
        if ($SendAsRemoved) {
            Write-Host "Send As removed" -ForegroundColor Green
        } else {
            Write-Host "Removing Send As cancelled" -ForegroundColor Red
            $Granted = $false
        }
        #>
    } catch { 
        Write-Host "Send As removal failed" -ForegroundColor Red
        # Write-Error $_
        # Write-Warning $_
        $Granted = $false 
    }
    return $Granted
}

function Set-SendOnBehalfAccess {
    param ($EmailBoxName, $UserName)
    $Granted = $true
    $EmailAddress = Get-Mailbox $UserName | Select-Object -ExpandProperty PrimarySmtpAddress
    Write-Host -NoNewline "Adding SendOn Behalf Access: "
    try { 
        # Add-ADPermission -Identity $EmailBoxName -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop
        Set-Mailbox -Identity $EmailBoxName -GrantSendOnBehalfTo @{add="$EmailAddress"} -ErrorAction Stop -WarningAction Stop
        Write-Host "Send On Behalf granted" -ForegroundColor Green
    } catch { 
        $Granted = $false
        Write-Host "Send On Behalf grant failed" -ForegroundColor Red
        Write-Warning $_
    }
    return $Granted
}

function Remove-SendOnBehalfAccess {
    param ($EmailBoxName, $UserName)
    $Granted = $true
    $EmailAddress = Get-Mailbox $UserName | Select-Object -ExpandProperty PrimarySmtpAddress
    Write-Host -NoNewline "Removing Send On Behalf Access: "
    try { 
        # Add-ADPermission -Identity $EmailBoxName -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop
        Set-Mailbox -Identity $EmailBoxName -GrantSendOnBehalfTo @{remove="$EmailAddress"} -WarningAction Stop -ErrorAction Stop
        Write-Host "Send On Behalf removed" -ForegroundColor Green 
    } catch { 
        Write-Host "Send On Behalf removal failed" -ForegroundColor Red
        # Write-Warning $_
        $Granted = $false
    }
    return $Granted
}

function Write-Note {
    param ($Identity)

    $ConfirmNote = Read-Host "Write a note? (y/n)"
    if ($ConfirmNote -ieq "y") {
        $TicketNumber = Read-Host "Ticket Number please"
        $Today = Get-Date -Format "dd-MMM-yyyy"
        $Note = "Mailbox Access Provided: $TicketNumber / $Today"
        Write-Host "Note: $Note"
        $Info = Get-ADUser $Identity -Properties info | %{ $_.info}  
        Set-ADUser $Identity -Replace @{info="$($Info) `r`n $Note"}
        Write-Host "Note Added" -ForegroundColor Green
    } else {
        Write-Host "Note cancelled" -ForegroundColor DarkGreen
    }
}

function Select-Mailbox {
    param ($EmailBoxName, $OperationChoice)
    do {
        if (!$EmailBoxName) {
            
            if ($OperationChoice -eq 1) {
                Write-Host -NoNewline "Please provide a target "
                Write-Host -NoNewline "User/Mailbox " -ForegroundColor Yellow
                $EmailBoxName = (Read-Host "Name").Trim()
            } else {
                Write-Host -NoNewline "Please provide a target "
                Write-Host -NoNewline "Shared Mailbox " -ForegroundColor Yellow
                $EmailBoxName = (Read-Host "Name").Trim()
            }

            if ($EmailBoxName) {
                # Mailbox name filter and selector
                Write-Host "Searching the mailbox..." -ForegroundColor DarkGreen
                try {
                    if ($OperationChoice -eq 1) {
                        $MailBoxList = Get-Mailbox "*$EmailBoxName*" -RecipientTypeDetails UserMailbox -ErrorAction Stop # | Select-Object Name,DisplayName,PrimarySmtpAddress
                    } else {
                        $MailBoxList = Get-Mailbox "*$EmailBoxName*" -RecipientTypeDetails SharedMailbox -ErrorAction Stop
                    }
                    $IsEmailBoxExist = $true
                } catch {
                    Write-Host -NoNewline "No match found. " -ForegroundColor Red
                    $IsEmailBoxExist = $false # "No"
                }

                # if the mail box with that keyword do exisit and they are multiple with ... 
                if ($IsEmailBoxExist) {
                    if ($MailBoxList.length -gt 1) {
                        $NumOfMailboxFound = $MailboxList.length
                        Write-Host "$NumOfMailboxFound match found" -ForegroundColor Magenta
                        # MailBoxList
                        $Number = 0
                        $MailBoxList | ForEach-Object {
                                New-Object psObject -Property @{'Number'=$Number;
                                                                'Name'= $_.Name; 
                                                                'Alias'=$_.alias;
                                                                'DisplayName'=$_.DisplayName;
                                                                'PrimarySmtpAddress' = $_.PrimarySmtpAddress
                                                            }
                                $Number ++
                            } | Format-Table Number, Name, Alias, DisplayName, PrimarySmtpAddress -AutoSize | Out-Host

                        $Number = $Number-1

                        # Input Validator
                        do {
                            $TryAgain = $false
                            Write-Host -NoNewline "Please Section the mailbox or "
                            $MailboxNumber = Read-Host "Press [x] to search another mailbox"

                            # Check if $MailboxNumber is numeric
                            if ($MailboxNumber -match "[0-9]") {
                                try {
                                    $MailboxNumber = [int]$MailboxNumber
                                } catch {
                                    Write-Host "Wrong Alphanumeric! Try again." -ForegroundColor Red
                                    # wrong alphnumeric form - go to do it again
                                    $TryAgain = $true
                                }

                                if($MailboxNumber -is [int]) {
                                    if ($MailboxNumber -gt $Number) {
                                        Write-Host "Too many numbers! Try again" -ForegroundColor Red
                                        # go to input again
                                        $TryAgain = $true
                                    } else {
                                        # Write-Host "Too small number- which is ok"
                                        $EmailBoxAlias = $MailBoxList[$MailboxNumber].Alias
                                        $EmailBoxAddress = $MailBoxList[$MailboxNumber].PrimarySmtpAddress
                                        try {
                                            # Get-Mailbox $EmailBoxAlias -ErrorAction Stop | Select-Object Name,Alias,DisplayName,PrimarySmtpAddress | Format-Table -AutoSize | Out-Host
                                            Get-Mailbox $EmailBoxAddress -ErrorAction Stop | Select-Object Name,Alias,DisplayName,PrimarySmtpAddress | Format-Table -AutoSize | Out-Host
                                            # Write-host "**************************** Test ********************************"
                                        } catch {
                                            Write-Warning "No email name found bro"
                                            $IsEmailBoxExist = $false # "No"
                                        }
                                    }
                                }
                            } elseif ($MailboxNumber -imatch "[a-z]|[A-Z]") {
                                # Write-Host 'Alphabet'
                                if ($MailboxNumber -ieq 'x') {
                                    # go to exit
                                    Write-Host "Exiting..." -ForegroundColor DarkGreen
                                    # Write-Host "Search Email again" -ForegroundColor DarkGreen
                                    $IsEmailBoxExist = $false # "No"
                                    # $TryAgain = $false
                                    $EmailBoxName = $null
                                } else {
                                    # go to itput again
                                    Write-host "Not x! Try again" -ForegroundColor Red
                                    $TryAgain = $true
                                }
                            } else {
                                Write-Host "Something else! Try again" -ForegroundColor Red
                                # go to input again
                                $TryAgain = $true
                            }
                        } while ($TryAgain)
                        # Write-Host "Emailbox Name is $EmailBoxName" -ForegroundColor Yellow
                    } else {
                        # $MailBoxList.length -le 1
                        # $MailBoxList.length -eq 0 cannot be pass because it's been filtered in the previous stage already
                        # so, $MailBoxList.lenght -eq 1 is only possible in this else statement

                        
                        Write-Host "1 match found" -ForegroundColor Green
                        $EmailBoxName = $MailBoxList[0]
                        $EmailBoxAddress = $MailBoxList[0].PrimarySmtpAddress
                        $EmailBoxAlias = $MailBoxList[0].Alias
                        # $EmailBoxAlias = Get-Mailbox "*$EmailBoxName*" | Select-Object Alias -ExpandProperty Alias
                        try {
                            Get-Mailbox "$EmailBoxAlias" -ErrorAction Stop | Select-Object Name,Alias,DisplayName,PrimarySmtpAddress | Format-Table -AutoSize | Out-Host
                            Get-Mailbox "$EmailBoxAddress" -ErrorAction Stop | Select-Object Name,Alias,DisplayName,PrimarySmtpAddress | Format-Table -AutoSize | Out-Host
                        } catch {
                            Write-Warning "No email name found bro"
                            $IsEmailBoxExist = $false # "No"
                        }
                    }

                } else {
                    Write-Host "Please try again" -ForegroundColor Red
                    $EmailBoxName = $false
                }
            } else {
                Write-Warning "Null - Email Name"
                $IsEmailBoxExist = $false
            }
        } else {
            $EmailBoxAlias = $EmailBoxName # not sure why this is 
            $IsEmailBoxExist = $true
        }
    } while (!$IsEmailBoxExist)

    Write-Host -NoNewline "Current Email Box selected : "
    # $Name = (Get-Mailbox -Identity $EmailBoxAlias | Select-Object Name).Name
    $Name = (Get-Mailbox -Identity $EmailBoxAddress | Select-Object Name).Name
    $Address = (Get-Mailbox -Identity $EmailBoxAddress | Select-Object PrimarySmtpAddress).PrimarySmtpAddress # you can just passon $EmailBoxAddress value
    Write-Host "$Name ($Address)" -ForegroundColor Green
    # return $EmailBoxAlias
    return $EmailBoxAddress
}

<#
function Select-User {
    param($UserName)

    do {
        $UserExist = $true
        if (!$UserName) {
            $UserName = Read-Host "Please provide User Name"
            try {
                $UserFullName = Get-ADUser -Identity $UserName -Properties DisplayName -ErrorAction Stop | select-object -expandproperty DisplayName
                Write-Host -NoNewline "Current User name selected : "
                Write-Host "$UserFullName`n`n" -ForegroundColor Green
                
            } catch {
                # Write-Warning $_
                Write-Host "Hey dude, The user does NOT exist! check it again!" -ForegroundColor Red
                $UserExist = $false
                $UserName = $null
            }
        }
    } while (!$UserExist)
    return $UserName
}
#>

function Select-User {
    [CmdletBinding()]
    param ($Identity)

    # if (!$Identity) { Write-Host "Please, provide" -ForegroundColor Red }

    do {
        $repeat = $false

        if (!$Identity) {
            $UserName = (Read-Host "User name or ID").Trim()
            # $UserName = $UserName.Trim()
        } else {
            $UserName = $Identity.Trim()
        }
        
        if($UserName) {
            if ($UserName.Split(" ").Count -gt 1) {
                # Write-Host "### Test: More than 1 ###"
                $First  = $UserName.Split(" ")[0] -replace ",", ""
                $Second = $UserName.Split(" ")[1]
                $First = "$First*"
                $Second = "$Second*"
                $UserNameList = get-aduser -Filter {((surname -like $First) -and (givenname -like $Second)) -or ((surname -like $Second) -and (givenname -like $First))}
            } else {
                # Write-Host "### Test: less than 1 ###"
                $UserName = "$UserName*"
                $UserNameList = Get-ADUser -Filter {Name -like $UserName -or GivenName -like $UserName -or Surname -like $UserName -or UserPrincipalName -like $UserName}
            }

            if ($usernamelist.length -gt 1) {
                $Number = 1
                $UserNameList |
                    ForEach-Object {New-Object psObject -Property @{'Number'=$Number;'SamAccountName'= $_.SamAccountName;'FirstName'=$_.GivenName;'LastName'=$_.SurName;'Email' = $_.UserPrincipalName};$Number ++} |
                    Format-Table Number, SamAccountName, FirstName, LastName, Email -AutoSize | Out-Host
                
                do {
                    $repeatchoice = $false
                    $choice = Read-host "Please select the user or [x] to try again"

                    if ($choice -match "[0-9]") {
                        $choice = [int]$choice
                        if ($choice -gt $usernamelist.length) {
                            write-host "too much number detected" -ForegroundColor Red
                            $repeatchoice = $true
                        } else { 
                            # right choice
                            $choice = $choice -1
                            
                            $username = $usernamelist[$choice].SamAccountName
                            # Write-Host "### Test $Uername ###"

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

                # $choice = $choice - 1
                # $username = $usernamelist[$choice].name
            } 
            elseif ($UserNameList.length -eq 0) {
                Write-Host "No user found" -ForegroundColor Red
                $repeat = $true
                $Identity = $null
            } 
            else {
                # Write-Host "### Test: list only 1 exactly ###"
                # Write-Host "User Name List: $UserNameList"
                $username = $UserNameList.SamAccountName

            }
        } else {
            Write-Host "No user Name or ID provided. Please, provide" -ForegroundColor Red
            $repeat = $true
        }
        
    } while ($repeat)

    # Write-Host "### Test: Username $UserName ###"
    $userfullname = get-aduser $UserName -Properties displayname | Select-Object -ExpandProperty displayname
    write-Host -NoNewline "User Name: "
    write-host $userfullname -ForegroundColor green
    return $username
}




function Write-Letter {
    param($UserName, $EmailBoxName, $Access)
    $ConfirmLetter = Read-Host "Print a letter? (y/n)"
    if ($ConfirmLetter -ieq "y") {
        $EmailBoxAddress =  (Get-Mailbox -Identity $EmailBoxName | Select-Object PrimarySmtpAddress).PrimarySmtpAddress
        # $EmailBoxName =     (Get-Mailbox -Identity $EmailBoxName | Select-Object Alias).Alias
        $UserFullName =     Get-ADUser -Identity $UserName -Properties DisplayName | select-object -expandproperty DisplayName

        $Today = Get-Date -Format "dd-MMM-yyyy"
        $Header = "Dear Customer,"

        $AddBothAccess =                "`r`nFull Access and Send As access has been provided to $UserFullName for mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $DelBothAccess =                "`r`nFull Access and Send As access has been removed from $UserFullName for mailbox(s): $EmailBoxAddress.`n`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $AddFullSendOnBehalfAccess =    "`r`nFull Access and Send on behalf access has been provided to $UserFullName for mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $DelFullSendOnBehalfAccess =    "`r`nFull Access and Send on behalf access has been removed from $UserFullName for mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $AddFullAccess =                "`r`n$UserFullName has been provided Full Access to mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $DelFullAccess =                "`r`n$UserFullName has been removed Full Access from mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $AddSendAsAccess =              "`r`n$UserFullName has been provided SendAs Access to mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $DelSendAsAccess =              "`r`n$UserFullName has been removed SendAs Access from mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $AddSendOnBehalfAccess =        "`r`n$UserFullName has been provided Send on behalf access to mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $DelSendOnBehalfAccess =        "`r`n$UserFullName has been removed Send on behalf access from mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"

        $Footer = "`r`nKind Regards,`r`n`r`nGovConnect Service Desk`r`nPhone: 1800 217 640`r`nPortal: https://portal.govconnect.nsw.gov.au"

        $Header | Out-File Letter.txt
        Switch ($Access) {
            'addfull'       { $AddFullAccess          | Out-File Letter.txt -Append }
            'addsendas'     { $AddSendAsAccess        | Out-File Letter.txt -Append }
            'addfullsendas' { $AddBothAccess          | Out-File Letter.txt -Append }
            'delfull'       { $DelFullAccess          | Out-File Letter.txt -Append }
            'delsendas'     { $DelSendAsAccess        | Out-File Letter.txt -Append }
            'delfullsendas' { $DelBothAccess          | Out-File Letter.txt -Append }
            'addsendon'     { $AddSendOnBehalfAccess  | Out-File Letter.txt -Append }
            'delsendon'     { $DelSendOnBehalfAccess  | Out-File Letter.txt -Append }
            'addfullsendon' { $AddFullSendOnBehalfAccess | Out-File Letter.txt -Append }
            'delfullsendon' { $DelFullSendOnBehalfAccess | Out-File Letter.txt -Append }
            default {Write-Host "Error"}

            # 7 # Set-SendOnBehalf
            # 8 # Remove-SendOnBehalf
            # 9 # Set-Both (Full & SendOnBehalf)
            # 0 # Remove-Both (Full & SendOnBehalf)
        }
        $Footer | Out-File Letter.txt -Append
        Notepad Letter.txt
        Write-Host "Letter printed" -ForegroundColor Green
    } else {
        Write-Host "Letter cancelled"
    }
}

function Show-MenuMailTypeSelection {
    param($OperationChoice)
    
    # Write-HOst "####Test: $OperationChoice ####"
    if (!$OperationChoice) {
        Write-Host "=================================================================================="
        Write-HOst "                              Select Operation"
        Write-Host "=================================================================================="
        Write-Host "    [1] User Mailbox"
        Write-HOst "    [2] Shared Mailbox"
        Write-Host "=================================================================================="
        
        do {
            $Choice = Read-Host "Choice"
            if (!$Choice) {
                Write-Host "Empty choice! Try again" -ForegroundColor DarkRed
            } else {
                if ($Choice -match '[1-2]') {
                    return $Choice
                } else {
                    Write-Host "Wrong choice! Try again" -ForegroundColor DarkRed
                    $Choice = $null
                }
            }
        } while (!$Choice)
    } else {
        # No display
        # Just return $OperationChoic variable
        return $OperationChoice
    }
}

function Show-MenuMailDelegation {
    param($UserName, $EmailBoxName, $OperationChoice)

    # Write-Host "### Test: $EmailBoxName ###"
    # $EmailBoxName =     (Get-Mailbox -Identity $EmailAlias | Select-Object Name).Name
    $UserFullName =     Get-ADUser -Identity $UserName -Properties DisplayName | select-object -expandproperty DisplayName
    $EmailName =  (Get-Mailbox -Identity $EmailBoxName | Select-Object Name).Name
    $EmailAddress =  (Get-Mailbox -Identity $EmailBoxName | Select-Object PrimarySmtpAddress).PrimarySmtpAddress

    Write-Host "=================================================================================="
    Write-Host -NoNewline " Target Email Box : "
    Write-Host "$EmailName - $EmailAddress" -ForegroundColor Green
    Write-Host -NoNewline " User Name        : "
    Write-Host "$UserFullName" -ForegroundColor Green
    Write-Host "=================================================================================="
    Write-Host "                         EMAIL DELEGATION OPERATION                               "
    Write-Host "----------------------------------------------------------------------------------"
    if ($OperationChoice -eq 1) {
    # User Mailbox
    Write-Host "  [1] Add FullAccess  [2] Add Send on Behalf  [3] Add Both (Full & SendOnBehalf)  "
    Write-Host "  [4] Del FullAccess  [5] Del Send on Behalf  [6] Del Both (Full & SendOnBehalf)  "
    Write-Host "  [7] Quit Operation                                                              "
    } else {
    # Shared Mailbox
    Write-Host "    [1] Add FullAccess        [2] Add SendAs        [3] Add Both (Full & SendAs)  "
    Write-Host "    [4] Del FullAccess        [5] Del SendAs        [6] Del Both (Full & SendAs)  "
    Write-Host "    [7] Quit Operation                                                            "
    }
    Write-Host "=================================================================================="
    
    do {
        $Choice = Read-Host "Please select"
        if (!$Choice) {
            Write-Host "Empty choice! Try again" -ForegroundColor DarkRed
        } else {
            if ($Choice -match '[1-7]') {
                # return $Access
                if ($OperationChoice -ieq 1) {
                    # User Mailbox
                    Switch ($Choice) {
                        1 { $Access = "addfull" }
                        2 { $Access = "addsendon" }
                        3 { $Access = "addfullsendon" }
                        4 { $Access = "delfull" }
                        5 { $Access = "delsendon" }
                        6 { $Access = "delfullsendon" }
                        default { $Access = 'x'}
                    }
                } else {
                    # Shared Mailbox
                    Switch ($Choice) {
                        1 { $Access = "addfull" }
                        2 { $Access = "addsendas" }
                        3 { $Access = "addfullsendas" }
                        4 { $Access = "delfull" }
                        5 { $Access = "delsendas" }
                        6 { $Access = "delfullsendas" }
                        default { $Access = 'x'}
                    }
                }
            } else {
                Write-Host "Wrong choice! Try again" -ForegroundColor DarkRed
                $Choice = $null
            }
        }
    } while (!$Choice)
    
    return $Access
}

function Show-MenuSub {
    Write-Host "=================================================================================="
    Write-Host "                        Please Select Operation"
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host "    [1] Do other operation on the same Mail Box & User"
    Write-Host "    [2] Change user"
    Write-Host "    [3] Change target Mailbox"
    Write-Host "    [4] Quit Menu"
    Write-Host "=================================================================================="

    do {
        $Choice = Read-Host "What do you want?"
        if (!$Choice) {
            Write-Host "Empty choice! Try again" -ForegroundColor DarkRed
        } else {
            if ($Choice -match '[1-4]') {
                return $Choice
            } else {
                Write-Host "Wrong choice! Try again" -ForegroundColor DarkRed
                $Choice = $null
            }
        }
    } while (!$Choice)
}

Connect-Exch

do {
    Clear-Host
    Show-MastheadLogo
    $ConfirmContinue = 'n'
    $OperationChoice = Show-MenuMailTypeSelection -OperationChoice $OperationChoice
    $EmailBoxName   = Select-Mailbox -EmailBoxName $EmailAddress -OperationChoice $OperationChoice # will retun mailbox address
    # $EmailBoxNameAddress   = Select-Mailbox -EmailBoxName $EmailBoxName -OperationChoice $OperationChoice # will retun mailbox alias
    # Write-Host "### Test $EmailBoxName ###"
    $UserName       = Select-User -Identity $UserName

    # $EmailBoxName =     (Get-Mailbox -Identity $EmailBoxName | Select-Object Alias).Alias
    # $EmailBoxAddress =  (Get-Mailbox -Identity $EmailBoxName | Select-Object PrimarySmtpAddress).PrimarySmtpAddress
    $UserFullName =     Get-ADUser -Identity $UserName -Properties DisplayName | select-object -expandproperty DisplayName
    do {
        $TryAgainAccess = $true
        $Access = Show-MenuMailDelegation -UserName $UserName -EmailBoxName $EmailBoxName -OperationChoice $OperationChoice

        Switch ($Access) {
            "addfull"   { $Granted = Set-FullAccess -EmailboxName $EmailBoxName -UserName $UserName }
            "addsendas" { $Granted = Set-SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName }
            "addsendon" { $Granted = Set-SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName }
            "delfull"   { $Granted = Remove-FullAccess -EmailboxName $EmailBoxName -UserName $UserName }
            "delsendas" { $Granted = Remove-SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName }
            "delsendon" { $Granted = Remove-SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName }
            "addfullsendas" { 
                $AddedFull = Set-FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                $AddedSendAs = Set-SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName
                $Granted = $AddedSendAs -or $AddedFull # Generous Letter Service Policy
            }
            "addfullsendon" {
                $AddedFull = Set-FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                $AddedSendOnBehalf = Set-SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName
                $Granted = $AddedSendOnBehalf -or $AddedFull
            }
            "delfullsendas" { 
                $RemovedFull = Remove-FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                $RemovedSendAs = Remove-SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName
                $Granted = $RemovedSendAs -or $RemovedFull # Generous Letter Service Policy
            }
            "delfullsendon" {
                $Removedfull = Remove-FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                $RemovedSendOnBehalf = Remove-SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName
                $Granted = $RemovedSendOnBehalf -or $RemovedFull
            }
            'x'
            { 
                Write-Host "Exit..." -ForegroundColor Yellow
                $TryAgainAccess = $false
                $Granted = $false
            }
        }
        
        if ($Granted) {
            Write-Letter -UserName $UserName -EmailBoxName $EmailBoxName -Access $Access
            Write-Note -Identity $UserName
        } else {
            # Write-Host "Letter service cancelled due to access grant error" -ForegroundColor DarkGreen
        }
        
        if ($Access -eq 'x') {
            $Choice = Show-MenuSub
            switch ($Choice) {
                1 # Do other operation on the same user
                { $TryAgainAccess = $true }
                2 # Change user
                {   $UserName = $null
                    $TryAgainAccess = $false
                    $ConfirmContinue = 'y'
                }
                3 # Change email box
                {   $EmailBoxName = $null
                    $EmailAddress = $null
                    $TryAgainAccess = $false
                    $ConfirmContinue = 'y'
                }
                4 # quit
                {   Write-Host "Quiting..." -ForegroundColor DarkGreen
                    $TryAgainAccess = $false
                    $ConfirmContinue = 'n'

                }
                default { 
                    Write-Warning "Wrong Choice! Select it again"
                    $Choice = $false
                }
            }
        }
    } while ($TryAgainAccess)

    if (!$ConfirmContinue -or $ConfirmContinue -ieq 'n') {
        $ConfirmContinue = Read-Host "Job finished. Try again?(y/n)"
        if ($ConfirmContinue -ieq 'y') {
            $EmailBoxName = $null
            $EmailAddress = $null
            $UserName = $null
            $OperationChoice = $null
        }
    }
} while ($ConfirmContinue -ieq 'y')

Get-PSSession | Remove-PSSession
Show-Bye