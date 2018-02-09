<#
Please change -Identity parmameter as to what you desire to search
#>

."$PSScriptRoot\includes\functions.ps1"

Write-Host "Connecting Exchange Server ... Please wait ..." -ForegroundColor Yellow
Get-ConnectExch

function Select-Mailbox {
    param ($EmailBoxName, $OperationChoice)

    do {
        if (!$EmailBoxName) {
            if ($OperationChoice -eq 1) {
                Write-Host -NoNewline "Please provide a target "
                Write-Host -NoNewline "User/Mailbox " -ForegroundColor Yellow
                $EmailBoxName = (Read-Host "Name").Trim()
            } 
            else {
                Write-Host -NoNewline "Please provide a target "
                Write-Host -NoNewline "Shared Mailbox " -ForegroundColor Yellow
                $EmailBoxName = (Read-Host "Name").Trim()
            }

            Write-Host "Searching the mailbox..." -ForegroundColor DarkGreen
            try {
                if ($OperationChoice -eq 1) {
                    $MailBoxList = Get-Mailbox "*$EmailBoxName*" -RecipientTypeDetails UserMailbox -ErrorAction Stop
                } else {
                    if ($EmailBoxName -match "@") {
                        $MailBoxList = Get-Mailbox $EmailBoxName -RecipientTypeDetails SharedMailbox -ErrorAction Stop
                    } else {
                        $MailBoxList = Get-Mailbox -Filter "(Name -like '*$EmailBoxName*') -or (Alias -like '*$EmailBoxName*') -or (EmailAddresses -like '*$EmailBoxName*')" -RecipientTypeDetails SharedMailbox -ErrorAction Stop
                    }
                }
                $IsEmailBoxExist = $true
            } catch {
                Write-Host -NoNewline "No match found! " -ForegroundColor Red
                $IsEmailBoxExist = $false
            }

            if ($MailBoxList) {
                if ($MailBoxList.count -gt 1) {
                    $NumOfMailboxFound = $MailboxList.Count
                    Write-Host "$NumOfMailboxFound match found" -ForegroundColor Magenta
                    $MailBoxList = $MailBoxList | Sort-Object PrimarySmtpAddress
                    $Number = 1
                    $List = @()
                    foreach ($Mailbox in $MailBoxList) {
                        $List += New-Object psObject -Property @{'Number'=$Number; 'Name'= $Mailbox.Name;'Alias'=$Mailbox.alias;'DisplayName'=$Mailbox.DisplayName;'PrimarySmtpAddress' = $Mailbox.PrimarySmtpAddress }
                        $Number ++
                    } 
                    $List | Format-Table Number, Name, PrimarySmtpAddress, Alias, DisplayName -AutoSize | Out-Host

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
                                    $EmailBoxAlias = $MailBoxList[$MailboxNumber-1].Alias
                                    $EmailBoxAddress = $MailBoxList[$MailboxNumber-1].PrimarySmtpAddress
                                    try {                                            
                                        Get-Mailbox $EmailBoxAddress -ErrorAction Stop | Select-Object Name,Alias,DisplayName,PrimarySmtpAddress | Format-Table -AutoSize | Out-Host
                                           
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
                    $EmailBoxAlias = $MailBoxList[0].Alias
                    Get-Mailbox "$EmailBoxAddress" -ErrorAction Stop | Select-Object Name,Alias,DisplayName,PrimarySmtpAddress | Format-Table -AutoSize | Out-Host
                }
            } 
            else {
                Write-Host "No math found. Please try again" -ForegroundColor Red
                $EmailBoxName = $false
                $IsEmailBoxExist = $false
            }
        }
        else {
            # $EmailBoxAddress = $EmailBoxName
            $IsEmailBoxExist = $false
        }
    } while ($IsEmailBoxExist -eq $false)

    $Name =    (Get-Mailbox -Identity $EmailBoxAddress | Select-Object Name).Name
    $Address = (Get-Mailbox -Identity $EmailBoxAddress | Select-Object PrimarySmtpAddress).PrimarySmtpAddress
    Write-Host -NoNewline "Current Email Box selected : "
    Write-Host "$Name ($Address)" -ForegroundColor Green
    
    return $EmailBoxAddress
}

Clear-Host
$sharedmailbox = Select-Mailbox -OperationChoice 2

Write-Host "Please wait while retrieving the list..." -ForegroundColor Yellow
# List Full Access
$Full = Get-MailboxPermission -Identity $sharedmailbox | Where-Object {($_.user -like "GOVNET\*") -and !($_.user -match " ") -and !($_.user -like "*Admin*") -and ($_.user -notlike "*CAMPBELM*") -and ($_.user -notlike "*SINGHC3*") -and ($_.user -notlike "*CHENGK2*") -and ($_.user -notlike "GOVNET\MC")}
$arr_fl = $full.user | % { $_ -replace "govnet\\", ""}

# List all users who have 'Send-As' permission
$SendAsList = Get-Mailbox -Identity $sharedmailbox | Get-ADPermission | where { ($_.ExtendedRights -like "*Send-As*") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Select-Object User
$arr_sa = $SendAsList.user | % { $_ -replace "govnet\\", ""}

# Lists
Write-Host "===== Full Access ====="
$arr_fl | % { (Get-ADUser $_ -Properties displayname).displayname } | sort -Unique

Write-Host "`n===== Send As Access ====="
$arr_sa | % { (Get-ADUser $_ -Properties displayname).displayname } | sort -Unique
Write-Host "================================================="