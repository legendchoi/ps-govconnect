<#
SharedEmail Version 2.3
.DESCRIPTION
v2.3 - O365 functionality added
v2.2 
v2.1 
v2.0 - bug fix when removing full & send as when it is cancelled which previously indicated as granted. It now show 'cencelled'
v1.8 - use 'alias' for selecting emailbox
#>

."$PSScriptRoot\includes\functions.ps1"
."$PSScriptRoot\includes\Letter-Service.ps1"

function Show-MastheadLogo {
    Write-Host ""
    Write-Host "                           Shared Mailbox Operation`n" -ForegroundColor Yellow
}

function Show-Bye {
    Write-Host "Bye"
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

function Set-O365FullAccess {
    param ($EmailboxName, $UserName)
    $Granted = $true
    $UserName = (Get-ADUser $UserName).UserPrincipalName
    Write-Host -NoNewline "Adding Full access: " -ForegroundColor DarkCyan
    try { 
        Add-O365MailboxPermission $EmailBoxName -User $UserName -AccessRights FullAccess -InheritanceType All -ErrorAction Stop -WarningAction Stop | Out-Null
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

function Remove-O365FullAccess {
    param ($EmailboxName, $UserName)
    $Granted = $true
    $UserName = (Get-ADUser $UserName).UserPrincipalName
    Write-Host -NoNewline "Removing Full access: " -ForegroundColor DarkCyan
    try { 
        Remove-O365MailboxPermission $EmailBoxName -User $UserName -AccessRights FullAccess -InheritanceType All  -Confirm:$false -ErrorAction Stop -WarningAction Stop | Out-Null
        Write-host "Full Access removed" -ForegroundColor Green
    } catch {
        Write-Host "Full Access removal failed" -ForegroundColor Red
        # Write-Warning $_
        $Granted = $false 
    }
    return $Granted
}

# Add-O365MailboxPermission "FMTraining" -User BURDANN -AccessRights FullAccess -InheritanceType All -Confirm:$false


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

function Set-O365SendAsAccess {
    param ($EmailboxName, $UserName)
    $Granted = $true
    $UserName = (Get-ADUser $UserName).UserPrincipalName
    Write-Host -NoNewline "Adding Send As access: " -ForegroundColor DarkCyan
    try {
        # Get-Mailbox $EmailboxName | Add-ADPermission -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop
        Add-O365RecipientPermission $EmailboxName -AccessRights SendAs -Trustee $UserName -Confirm:$false -ErrorAction Stop -WarningAction Stop
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
    } catch { 
        Write-Host "Send As removal failed" -ForegroundColor Red
        $Granted = $false 
    }
    return $Granted
}

function Remove-O365SendAsAccess {
    param ($EmailboxName, $UserName)
    $Granted = $true
    $UserName = (Get-ADUser $UserName).UserPrincipalName
    Write-Host -NoNewline "Removing Send As access: " -ForegroundColor DarkCyan
    try { 
        # Get-Mailbox $EmailBoxName | Remove-ADPermission -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop -Confirm:$false
        Remove-O365RecipientPermission $EmailBoxName -AccessRights SendAs -Trustee $UserName -Confirm:$false -ErrorAction Stop -WarningAction Stop
        Write-Host "Send As removed" -ForegroundColor Green
    } catch { 
        Write-Host "Send As removal failed" -ForegroundColor Red
        $Granted = $false 
    }
    return $Granted
}

function Set-SendOnBehalfAccess {
    param ($EmailBoxName, $UserName)
    $Granted = $true
    $EmailAddress = Get-Mailbox $UserName | Select-Object -ExpandProperty PrimarySmtpAddress
    Write-Host -NoNewline "Adding SendOn Behalf Access: " -ForegroundColor DarkCyan
    try { 
        # Add-ADPermission -Identity $EmailBoxName -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop
        Set-Mailbox -Identity $EmailBoxName -GrantSendOnBehalfTo @{add="$EmailAddress"} -ErrorAction Stop -WarningAction Stop
        Write-Host "Send On Behalf granted" -ForegroundColor Green
    } catch { 
        $Granted = $false
        Write-Host "Send On Behalf grant failed. Maybe the user already has granted the 'on behalf' access previously" -ForegroundColor Red
        # Write-Warning $_
    }
    return $Granted
}

function Set-O365SendOnBehalfAccess {
    param ($EmailBoxName, $UserName)
    $Granted = $true
    $UserName = (Get-ADUser $UserName).UserPrincipalName
    $EmailAddress = Get-O365Mailbox $UserName | Select-Object -ExpandProperty PrimarySmtpAddress
    Write-Host -NoNewline "Adding SendOn Behalf Access: " -ForegroundColor DarkCyan
    try { 
        # Add-ADPermission -Identity $EmailBoxName -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop
        # Set-O365Mailbox -Identity $EmailBoxName -GrantSendOnBehalfTo @{add="$EmailAddress"} -ErrorAction Stop -WarningAction Stop
        Set-O365Mailbox -Identity $EmailBoxName -GrantSendOnBehalfTo $UserName -ErrorAction Stop -WarningAction Stop
        Write-Host "Send On Behalf granted" -ForegroundColor Green
    } catch { 
        $Granted = $false
        Write-Host "Send On Behalf grant failed. Maybe the user already has granted the 'on behalf' access previously" -ForegroundColor Red
        # Write-Warning $_
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

function Remove-O365SendOnBehalfAccess {
    param ($EmailBoxName, $UserName)
    $Granted = $true
    $UserName = (Get-ADUser $UserName).UserPrincipalName
    $EmailAddress = Get-O365Mailbox $UserName | Select-Object -ExpandProperty PrimarySmtpAddress
    Write-Host -NoNewline "Removing Send On Behalf Access: "
    try { 
        # Add-ADPermission -Identity $EmailBoxName -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop
        Set-O365Mailbox -Identity $EmailBoxName -GrantSendOnBehalfTo @{remove="$EmailAddress"} -WarningAction Stop -ErrorAction Stop
        Write-Host "Send On Behalf removed" -ForegroundColor Green 
    } catch { 
        Write-Host "Send On Behalf removal failed" -ForegroundColor Red
        # Write-Warning $_
        $Granted = $false
    }
    return $Granted
}
function Write-Note {
    param ($Identity,$Access,$EmailBoxName)

    # $ConfirmNote = Read-Host "Write a note? (y/n)"
    # Write-Host "Test1: $Identity"
    $ConfirmNote = 'y'
    if ($ConfirmNote -ieq "y") {
        $TicketNumber = Read-Host "Ticket Number please"
        $Today = Get-Date -Format "dd-MMM-yyyy"
        $Note = "Mailbox Access modified - $Access for $EmailBoxName : $TicketNumber / $Today"
        Write-Host "Note: $Note"
        $Info = Get-ADUser $Identity -Properties info | %{ $_.info}  
        Set-ADUser $Identity -Replace @{info="$Info `r`n $Note"}
        Write-Host "Note Added" -ForegroundColor Green
    } else {
        Write-Host "Note cancelled" -ForegroundColor DarkGreen
    }
}

function Select-Mailbox {
    param ($EmailBoxName, $OperationChoice)
    # Write-Host "Test2: Email Box Name = $EmailBoxName"

    do {
        if (!$EmailBoxName) {
            do {
                switch ($OperationChoice) {
                    1 {
                        # Write-Host "Selection 1"
                        Write-Host -NoNewline "Please provide a target "
                        Write-Host -NoNewline "User/Mailbox " -ForegroundColor Yellow
                        $EmailBoxName = (Read-Host "Name").Trim()
                    }
                    2 {
                        # Write-Host "Selection 2"
                        Write-Host -NoNewline "Please provide a target "
                        Write-Host -NoNewline "Shared Mailbox " -ForegroundColor Yellow
                        $EmailBoxName = (Read-Host "Name").Trim()
                    }
                    3 {
                        # Write-Host "Selection 3"
                        Write-Host -NoNewline "Please provide a target "
                        Write-Host -NoNewline "Room Mailbox " -ForegroundColor Yellow
                        $EmailBoxName = (Read-Host "Name").Trim()
                    }
                    4 {
                        # Write-Host "Selection 4"
                        Write-Host -NoNewline "Please provide a target "
                        Write-Host -NoNewline "Equipment Mailbox " -ForegroundColor Yellow
                        $EmailBoxName = (Read-Host "Name").Trim()
                    }
                    default {
                        Write-Host "Quit"
                    }
                }

                <#
                if ($OperationChoice -eq 1) {
                    
                } 
                elseif ($OperationChoice -eq 2) {

                }
                elseif ($OperationChoice -eq 3) {

                }
                else {

                }
                #>
                if (!$EmailBoxName) { Write-Warning "Null value found. Please provide the emailbox name" }
            } while (!$EmailBoxName)
            

            if ($OperationChoice -ne 0) {
                Write-Host "Searching the mailbox..." -ForegroundColor DarkGreen
            }
            

            # New Search Process - now search On-Premises exch & O365 mailbox
            $MailBoxList = @()

            <#
            Switch ($OperationChoice) {
                "1" {}
                "2" {}
                "3" {}
                "4" {}
                default {}
            }
            #>

            if ($OperationChoice -eq 1) {
                try {
                    $MailBoxList += Get-Mailbox "*$EmailBoxName*" -RecipientTypeDetails UserMailbox -ErrorAction Stop
                } catch { <# do nothing #> }

                [string]$Filter = "(RecipientTypeDetails -eq `"UserMailbox`" -and name -like `"*$EmailBoxName*`")"
                try {
                    $MailBoxList += Get-O365Mailbox -Filter $Filter -ErrorAction Stop
                } catch {
                    # just null
                    # Write-Host "No usermail found in O365"
                }
            } else {
                # $MailBoxList = @()

                if ($EmailBoxName -match "@") {
                    try {
                        $MailBoxList += Get-Mailbox $EmailBoxName -RecipientTypeDetails SharedMailbox -ErrorAction Stop
                    } catch {
                        # Just Null
                        Write-Host "Test1"
                    }
                    try {
                        $MailBoxList += Get-O365Mailbox $EmailBoxName -RecipientTypeDetails SharedMailbox -ErrorAction Stop
                    } catch {
                        # just null
                        Write-Host "Test2"
                    }
                } else {
                    try {
                        $MailBoxList += Get-Mailbox -Filter "(DisplayName -like '*$EmailBoxName*') -or (Name -like '*$EmailBoxName*') -or (Alias -like '*$EmailBoxName*') -or (EmailAddresses -like '*$EmailBoxName*')" -RecipientTypeDetails SharedMailbox -ErrorAction Stop
                    } catch {
                        # Just Null
                        Write-Host "Test3"
                    }
                    try {
                        $MailBoxList += Get-O365Mailbox -Filter "(DisplayName -like '*$EmailBoxName*') -or (Name -like '*$EmailBoxName*') -or (Alias -like '*$EmailBoxName*') -or (EmailAddresses -like '*$EmailBoxName*')" -RecipientTypeDetails SharedMailbox -ErrorAction Stop
                    } catch {
                        # just null
                        Write-Host "Test4"
                    }
                }
            }
            
            # this if-Statement block may not be necessary - Duplicated with the next If-Statement
            <#
            if ($MailBoxList) {
                $IsEmailBoxExist = $true
            } else {
                Write-Host -NoNewline "No match found! " -ForegroundColor Red
                $IsEmailBoxExist = $false
            }
            #>
            
            if ($MailBoxList) {
                if ($MailBoxList.count -gt 1) {
                    $NumOfMailboxFound = $MailboxList.Count
                    Write-Host "$NumOfMailboxFound match found" -ForegroundColor Magenta
                    $MailBoxList = $MailBoxList | Sort-Object PrimarySmtpAddress
                    $Number = 1
                    $List = @()
                    foreach ($Mailbox in $MailBoxList) {
                        $List += New-Object psObject -Property @{'Number'=$Number; 'Name'= $Mailbox.Name;'Alias'=$Mailbox.alias;'DisplayName'=$Mailbox.DisplayName;'PrimarySmtpAddress' = $Mailbox.PrimarySmtpAddress; 'ServerName'=$Mailbox.ServerName;'OriginatingServer'=$Mailbox.OriginatingServer}
                        $Number ++
                    } 
                    $List | Format-Table Number, Name, PrimarySmtpAddress, Alias, DisplayName, ServerName, OriginatingServer -AutoSize | Out-Host

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
                                $TryAgain = $true
                            }

                            if($MailboxNumber -is [int]) {
                                if ($MailboxNumber -gt $Number) {
                                    Write-Host "Too many numbers! Try again" -ForegroundColor Red
                                    # go to input again
                                    $TryAgain = $true
                                } else {
                                    # Write-Host "Too small number- which is ok"
                                    # $EmailBoxAlias = $MailBoxList[$MailboxNumber-1].Alias
                                    $EmailBoxSelected = $MailBoxList[$MailboxNumber-1]
                                    $EmailBoxAddress = $MailBoxList[$MailboxNumber-1].PrimarySmtpAddress
                                    # Write-Host "$EmailBoxSelected"
                                    # Write-Host ($EmailBoxSelected).OriginatingServer
                                    try {                                            
                                        if (($EmailBoxSelected).OriginatingServer -imatch "outlook.com") {
                                            Get-O365Mailbox $EmailBoxAddress -ErrorAction Stop | Select-Object Name,Alias,DisplayName,PrimarySmtpAddress | Format-Table -AutoSize | Out-Host
                                        } else {
                                            Get-Mailbox $EmailBoxAddress -ErrorAction Stop | Select-Object Name,Alias,DisplayName,PrimarySmtpAddress | Format-Table -AutoSize | Out-Host
                                        }
                                           
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
                } 
                else {
                    Write-Host "1 match found" -ForegroundColor Green
                    $EmailBoxName = $MailBoxList[0]
                    $EmailBoxAddress = $MailBoxList[0].PrimarySmtpAddress
                    # $EmailBoxAlias = $MailBoxList[0].Alias
                    $EmailBoxSelected = $MailBoxList[$MailboxNumber-1]
                    Get-Mailbox "$EmailBoxAddress" -ErrorAction Stop | Select-Object Name,Alias,DisplayName,PrimarySmtpAddress,ServerName | Format-Table -AutoSize | Out-Host
                }
            } 
            else {
                Write-Host "No math found. Please try again" -ForegroundColor Red
                $EmailBoxName = $false
                $IsEmailBoxExist = $false
            }
        }
        else {
            try {
                # Write-Host "Test1"
                $EmailBoxSelected = Get-Mailbox $EmailBoxName -ErrorAction Stop
                $IsEmailBoxExist = $true
            } catch {
                # Write-Host "Test2"
                $EmailBoxSelected = Get-O365Mailbox $EmailBoxName -ErrorAction Stop
                $IsEmailBoxExist = $true
            } finally {
                $Error
            }
            # $EmailBoxAddress = $EmailBoxName
            # $IsEmailBoxExist = $true
        }
    } while ($IsEmailBoxExist -eq $false)

    $Name =    ($EmailBoxSelected).Name
    $Address = ($EmailBoxSelected).PrimarySmtpAddress

    Write-Host -NoNewline "Current Email Box selected : "
    Write-Host "$Name ($Address)" -ForegroundColor Green
    
    return $EmailBoxSelected
}

<#
function Write-Letter {
    param($UserName, $EmailBoxName, $Access)
    # $ConfirmLetter = Read-Host "Print a letter? (y/n)"
    $ConfirmLetter = 'y'
    if ($ConfirmLetter -ieq "y") {
        $EmailBoxAddress =  (Get-Mailbox -Identity $EmailBoxName | Select-Object PrimarySmtpAddress).PrimarySmtpAddress
        # $EmailBoxName =     (Get-Mailbox -Identity $EmailBoxName | Select-Object Alias).Alias
        $UserFullName =     Get-ADUser -Identity $UserName -Properties DisplayName | select-object -expandproperty DisplayName

        $Today = Get-Date -Format "dd-MMM-yyyy"
        $AgentName = $env:USERNAME
        $AgentDisplayName = (Get-ADUser $AgentName -Properties DisplayName).DisplayName
        $AgentExtNumber = Get-ExtNumber

        $Header = "Dear [Customer] ,"

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

        $Footer = "`r`nKind Regards,`r`n`r`n$AgentDisplayName`r`nGovConnect Service Desk`r`nPhone: 1800 217 640`r`nDirect:1300 666 277 ext#$AgentExtNumber (To be used in regards to the above Incident/Request only)`r`nPortal: https://portal.govconnect.nsw.gov.au"

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
#>

function Show-MenuMailTypeSelection {
    param($OperationChoice)
    
    # Write-HOst "####Test: $OperationChoice ####"
    if (!$OperationChoice) {
        Write-Host "=================================================================================="
        Write-HOst "                              Select Operation"
        Write-Host "=================================================================================="
        Write-Host "    [1] User Mailbox"
        Write-HOst "    [2] Shared Mailbox"
        # Write-HOst "    [3] Room Mailbox (Resources)"
        # Write-HOst "    [4] Equipment Mailbox"
        # Write-HOst "    [0] Quit"
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

function Get-DelegationInfo {
    param(
        $GrantSendOnBehalfToMatch,
        $FullAccessMatch,
        $SendAsMatch
    )

    if ($GrantSendOnBehalfToMatch -or $FullAccessMatch -or $SendAsMatch) {
        Write-Host "                               INfO"
        Write-Host "----------------------------------------------------------------------------------"
        if ($grantsendonbehalftoMatch) {
            Write-Host "The User $UserFullName has been granted 'Send on behalf to' on $EmailAddress" -ForegroundColor DarkYellow
        }
        if ($FullAccessMatch) {
            Write-Host "The User $UserFullName has been granted 'Full Access' on $EmailAddress" -ForegroundColor DarkYellow
        }
        if ($sendasMatch) {
            Write-Host "The User $UserFullName has been granted 'Send as' on $EmailAddress" -ForegroundColor DarkYellow
        }

        Write-Host "----------------------------------------------------------------------------------"
    } else {}
}

function Show-MenuMailDelegation {
    param($UserName, $EmailBox, $OperationChoice)

    $EmailName =        $EmailBox.Name
    $EmailBoxName =     $EmailBox.PrimarySmtpAddress
    $EmailAddress =     $EmailBox.PrimarySmtpAddress
    $OriginatingServer = $EmailBox.OriginatingServer
    $UserFullName =     Get-ADUser -Identity $UserName -Properties DisplayName | select-object -expandproperty DisplayName
    $User = Get-ADUser -Identity $UserName
    $upn = $User.UserPrincipalName
    $NameOfUser = $User.Name
    
    if ($OriginatingServer -imatch "outlook.com") {
        (Get-O365Mailbox $EmailBoxName).grantsendonbehalfto | Out-Host
        $grantsendonbehalftoMatch = (Get-O365Mailbox $EmailBoxName).grantsendonbehalfto -imatch $NameOfUser
        $FullAccessMatch =          ((Get-O365MailboxPermission -Identity $EmailBoxName | ? {$_.AccessRights -eq "FullAccess"}).User) -imatch $upn
        $sendasMatch =              ((Get-O365RecipientPermission $EmailBoxName | ? {$_.AccessRights -eq "SendAs"}).Trustee) -imatch $upn
    } else {
        $grantsendonbehalftoMatch = (Get-Mailbox $EmailBoxName).grantsendonbehalfto -imatch $UserName
        $FullAccessMatch =          ((Get-MailboxPermission -Identity $EmailBoxName | ? {$_.AccessRights -eq "FullAccess"}).User) -imatch $UserName
        $sendasMatch =              ((Get-Mailbox $EmailBoxName | Get-ADPermission | ? {$_.ExtendedRights -like "*Send-AS*"}).user) -imatch $UserName
    }


    Write-Host "=================================================================================="
    Write-Host -NoNewline " Target Email Box : "
    Write-Host "$EmailName - $EmailAddress" -ForegroundColor Green
    Write-Host -NoNewline " User Name        : "
    Write-Host "$UserFullName" -ForegroundColor Green
    Write-Host "=================================================================================="

    Get-DelegationInfo -GrantSendOnBehalfToMatch $grantsendonbehalftoMatch -FullAccessMatch $FullAccessMatch -SendAsMatch $sendasMatch


    Write-Host "                         EMAIL DELEGATION OPERATION                               "
    Write-Host "----------------------------------------------------------------------------------"
    if ($OperationChoice -eq 1) {
    # User Mailbox
    Write-Host "  [1] Add FullAccess  [2] Add Send on Behalf  [3] Add Both (Full & SendOnBehalf)  "
    Write-Host "  [4] Del FullAccess  [5] Del Send on Behalf  [6] Del Both (Full & SendOnBehalf)  "
    Write-Host "  [0] Go Menu"
    } else {
    # Shared Mailbox
    Write-Host "    [1] Add FullAccess        [2] Add SendAs        [3] Add Both (Full & SendAs)  "
    Write-Host "    [4] Del FullAccess        [5] Del SendAs        [6] Del Both (Full & SendAs)  "
    Write-Host "    [0] Go Menu"
    }
    Write-Host "=================================================================================="
    
    do {
        $Choice = Read-Host "Please select"
        if (!$Choice) {
            Write-Host "Empty choice! Try again" -ForegroundColor DarkRed
        } else {
            if ($Choice -match '[0-6]') {
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
    Write-Host "    [1] Go back to previous menu"
    Write-Host "    [2] Change user"
    Write-Host "    [3] Change target Mailbox"
    Write-Host "    [4] Quit Menu (to change both user & Mailbox)"
    Write-Host "    [0] Quit Program (to go back to main menu)"
    Write-Host "=================================================================================="

    do {
        $Choice = Read-Host "What do you want?"
        if (!$Choice) {
            Write-Host "Empty choice! Try again" -ForegroundColor DarkRed
        } else {
            if ($Choice -match '[0-4]') {
                return $Choice
            } else {
                Write-Host "Wrong choice! Try again" -ForegroundColor DarkRed
                $Choice = $null
            }
        }
    } while (!$Choice)
}



# Main Operations

# Connecting Exchange sessions
Connect-Exch
Connect-Office365

do {
    Clear-Host
    Show-MastheadLogo
    # Write-Host "Test: Email Address = $EmailAddress"
    # Write-Host "Test: Email Box Name = $EmailBoxName"
    
    $ConfirmContinue = 'n'
    $OperationChoice = Show-MenuMailTypeSelection -OperationChoice $OperationChoice
    $EmailBox        = Select-Mailbox -EmailBoxName $EmailBoxName -OperationChoice $OperationChoice # will retun mailbox object
    $EmailBoxName    = $EmailBox.PrimarySmtpAddress
    $OriginatingServer = $EmailBox.OriginatingServer
    $UserName        = Select-User -Identity $UserName
    $UserFullName    = Get-ADUser -Identity $UserName -Properties DisplayName | select-object -expandproperty DisplayName
    do {
        $TryAgainAccess = $true
        # $Access = Show-MenuMailDelegation -UserName $UserName -EmailBoxName $EmailBoxName -OperationChoice $OperationChoice
        $Access = Show-MenuMailDelegation -UserName $UserName -EmailBox $EmailBox -OperationChoice $OperationChoice
        Switch ($Access) {
            "addfull"   {
                if($OriginatingServer -imatch "outlook.com"){
                    $Granted = Set-O365FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                } else {
                    $Granted = Set-FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                }
            }
            "addsendas" { 
                if($OriginatingServer -imatch "outlook.com"){
                    $Granted = Set-O365SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName
                } else {
                    $Granted = Set-SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName 
                }
            }
            "addsendon" { 
                if($OriginatingServer -imatch "outlook.com"){
                    $Granted = Set-O365SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName
                } else {
                    $Granted = Set-SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName
                }
            }
            "delfull"   {
                if($OriginatingServer -imatch "outlook.com"){
                    $Granted = Remove-O365FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                } else {
                    $Granted = Remove-FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                }
            }
            "delsendas" { 
                if($OriginatingServer -imatch "outlook.com"){
                    $Granted = Remove-O365SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName
                } else {
                    $Granted = Remove-SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName
                }
            }
            "delsendon" { 
                if($OriginatingServer -imatch "outlook.com"){
                    $Granted = Remove-O365SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName 
                } else {
                    $Granted = Remove-SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName 
                }
            }
            "addfullsendas" {
                if($OriginatingServer -imatch "outlook.com"){
                    $AddedFull = Set-O365FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                    $AddedSendAs = Set-O365SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName
                } else {
                    $AddedFull = Set-FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                    $AddedSendAs = Set-SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName
                }
                $Granted = $AddedSendAs -or $AddedFull # Generous Letter Service Policy
                # $Access = 'x'
            }
            "addfullsendon" {
                if($OriginatingServer -imatch "outlook.com"){
                    $AddedFull = Set-O365FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                    $AddedSendOnBehalf = Set-O365SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName
                } else {
                    $AddedFull = Set-FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                    $AddedSendOnBehalf = Set-SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName
                }
                $Granted = $AddedSendOnBehalf -or $AddedFull
                # $Access = 'x'
            }
            "delfullsendas" {
                if($OriginatingServer -imatch "outlook.com"){
                    $RemovedFull = Remove-O365FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                    $RemovedSendAs = Remove-O365SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName
                } else {
                    $RemovedFull = Remove-FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                    $RemovedSendAs = Remove-SendAsAccess -EmailboxName $EmailBoxName -UserName $UserName
                }
                $Granted = $RemovedSendAs -or $RemovedFull # Generous Letter Service Policy
                # $Access = 'x'
            }
            "delfullsendon" {
                if($OriginatingServer -imatch "outlook.com"){
                    $Removedfull = Remove-O365FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                    $RemovedSendOnBehalf = Remove-O365SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName
                } else {
                    $Removedfull = Remove-FullAccess -EmailboxName $EmailBoxName -UserName $UserName
                    $RemovedSendOnBehalf = Remove-SendOnBehalfAccess -EmailBoxName $EmailBoxName -UserName $UserName
                }
                $Granted = $RemovedSendOnBehalf -or $RemovedFull
                # $Access = 'x'
            }
            'x'
            { 
                Write-Host "Exit..." -ForegroundColor Yellow
                $TryAgainAccess = $false
                $Granted = $false
            }
        }
        
        if ($Granted) {
            Write-Note -Identity $UserName -Access $Access -EmailBoxName $EmailBoxName
            Write-SMLetter -UserName $UserName -EmailBoxName $EmailBoxName -Access $Access
        } else {
            # Write-Host "Letter service cancelled due to access grant error" -ForegroundColor DarkGreen
        }

        # Get the submenu to come up stright away
        $Access = 'x'
        
        if ($Access -eq 'x') {
            $Choice = Show-MenuSub
            switch ($Choice) {
                0 # Quit Program
                { 
                    $TryAgainAccess = $false
                    $ConfirmContinue = 'n'
                }
                1 # Go back to previous menu
                { $TryAgainAccess = $true }
                2 # Change user
                {   $UserName = $null
                    $TryAgainAccess = $false
                    $ConfirmContinue = 'y'
                    # Write-Host "Test: Email Address = $EmailAddress"
                    # Write-Host "Test: Email Box Name = $EmailBoxName"
                }
                3 # Change target Mailbox
                {   $EmailBoxName = $null
                    $EmailAddress = $null
                    $TryAgainAccess = $false
                    $ConfirmContinue = 'y'
                }
                4 # Quit Menu (to change both user & Mailbox)
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
        # write-Host "YOur Choice: $Choice"
        if (($Choice -eq 0) ) {
            # Write-Host "No continue"
            $ConfirmContinue = 'n'
        } elseif ($Choice -eq 4) {
            $ConfirmContinue = 'y'
        } else {
            $ConfirmContinue = Read-Host "Job finished. Try again?(y/n)"
        }
        
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