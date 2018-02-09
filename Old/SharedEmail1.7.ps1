<#
SharedEmail Version 1.4
Created by Hyun Choi (Hyun.Choi@au.unisys.com)

.DESCRIPTION
This script may have bugs and I am still developing the code. You may use this script on your own risk.
#>


# Function to create Exchange PSSession 
Function Get-ConnectExch {
	Param (
        [parameter()]
		[string]$ConnectionUri = "http://dc1wexcamb01.govnet.nsw.gov.au/PowerShell/"
	)
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri
    Import-Module (Import-PSSession $session -AllowClobber) -Global
}

$Logo = "
 _____            _____                             _   _   _  _____  _    _ 
|  __ \          /  __ \                           | | | \ | |/  ___|| |  | |
| |  \/ _____   _| /  \/ ___  _ __  _ __   ___  ___| |_|  \| |\ '--. | |  | |
| | __ / _ \ \ / / |    / _ \| '_ \| '_ \ / _ \/ __| __| . ' | '--. \| |/\| |
| |_\ \ (_) \ V /| \__/\ (_) | | | | | | |  __/ (__| |_| |\  |/\__/ /\  /\  /
 \____/\___/ \_/  \____/\___/|_| |_|_| |_|\___|\___|\__\_| \_/\____/  \/  \/ 

                                                                    - Unisys
"
$Bye = "
End of service
 ____
/\  _'\                    
\ \ \L\ \  __  __     __   
 \ \  _ <'/\ \/\ \  /'__'\ 
  \ \ \L\ \ \ \_\ \/\  __/ 
   \ \____/\/'____ \ \____\
    \/___/  '/___/> \/____/
               /\___/      
               \/__/"

# Check if existing PSSession exist
if (!(Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" })) { 
    Write-Host "Connecting Exchange Server... `nPlease wait..." -ForegroundColor DarkGreen
    Get-ConnectExch
}

Clear-Host
Write-Host $Logo -ForegroundColor Yellow
do {
    $ConfirmContinue = 'n'

    # Email Address Checking
    do {
        # $IsEmailBoxExist = "Yes"
        if (!$EmailBoxName) {
            $EmailBoxName = Read-Host "Please provide Mailbox Name"

            if ($EmailBoxName) {
                # Mailbox name filter and selector
                Write-Host "Searching the mailbox..." -ForegroundColor DarkGreen
                try {
                    $MailBoxList = Get-Mailbox "*$EmailBoxName*" -ErrorAction Stop # | Select-Object Name,DisplayName,PrimarySmtpAddress
                    # $MailBoxList
                    $IsEmailBoxExist = $true
                    # $IsEmailBoxExist
                } catch {
                    # Write-Warning $_
                    Write-Host "No match found" -ForegroundColor Red
                    $IsEmailBoxExist = $false # "No"
                    # $IsEmailBoxExist
                }

                # if the mail box with that keyword do exisit and they are multiple with ... 
                if ($IsEmailBoxExist) {
                    
                    if ($MailBoxList.length -gt 1) {
                        $NumOfMailboxFound = $MailboxList.length
                        Write-Host "$NumOfMailboxFound match found" -ForegroundColor Magenta
                        # MailBoxList
                        $Number = 0
                        $MailBoxList |
                            ForEach-Object {New-Object psObject -Property @{'Number'=$Number;'Name'= $_.Name; 'DisplayName'=$_.DisplayName;'PrimarySmtpAddress' = $_.PrimarySmtpAddress};$Number ++} |
                            Format-Table Number, Name, DisplayName, PrimarySmtpAddress -AutoSize

                        $Number = $Number-1

                        # Input Validator
                        do {
                            $TryAgain = $false
                            Write-Host "Please Section the mailbox OR"
                            $MailboxNumber = Read-Host "Press [x] to search a mailbox agian"
                            # $MailboxNumber -is [int]
                            # $Number
                            # Check if $MailboxNumber is numeric
                            if ($MailboxNumber -match "[0-9]") {
                                # Write-Host 'number'
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
                                        $EmailBoxName = $MailBoxList[$MailboxNumber].Name
                                        try {
                                            Get-Mailbox $EmailBoxName -ErrorAction Stop | Select-Object Name,DisplayName,PrimarySmtpAddress | Format-Table -AutoSize
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
                                    $EmailBoxName = $false
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
                        Write-Host "1 match found" -ForegroundColor Green
                        $EmailBoxName = Get-Mailbox "*$EmailBoxName*" | Select-Object Name -ExpandProperty Name
                        # Write-Host "+------------------------------------------------------------------+"
                        # Write-Host -NoNewline "Current Email Box selected : "
                        # Write-Host "$EmailBoxName`n`n" -ForegroundColor Green
                        # Write-Host "+------------------------------------------------------------------+"
                        try {
                            Get-Mailbox "$EmailBoxName" -ErrorAction Stop | Select-Object Name,DisplayName,PrimarySmtpAddress | Format-Table -AutoSize
                            # Write-Host "Proceed Next >>>" -ForegroundColor DarkGreen
                        } catch {
                            Write-Warning "No email name found bro"
                            $IsEmailBoxExist = $false # "No"
                        }
                    }

                    # Write-Host "+------------------------------------------------------------------+"
                    Write-Host -NoNewline "Current Email Box selected : "
                    Write-Host "$EmailBoxName`n`n" -ForegroundColor Green
                    # Write-Host "+------------------------------------------------------------------+"

                } else {
                    # Write-Warning "No match found"
                    Write-Host "Please try again" -ForegroundColor Red
                    $EmailBoxName = $false
                }
            } else {
                Write-Warning "Null - Email Name"
                $IsEmailBoxExist = "No"
            }
        }
    } while (!$IsEmailBoxExist<# -eq "No"#>)

    # Write-Host "+------------------------------------------------------------------+"
    # Write-Host -NoNewline "Current Email Box selected : "
    # Write-Host "$EmailBoxName`n`n" -ForegroundColor Green
    # Write-Host "+------------------------------------------------------------------+"
    
	$EmailBoxAddress = (Get-Mailbox -Identity $EmailBoxName | Select-Object PrimarySmtpAddress).PrimarySmtpAddress
    $EmailBoxName = (Get-Mailbox -Identity $EmailBoxName | Select-Object Name).Name
    
    #User checking
    do {
        $NoUserExist = $false
        if (!$UserName) {
            $UserName = Read-Host "Please provide User Name"
            try {
                $UserFullName = Get-ADUser -Identity $UserName -Properties DisplayName -ErrorAction Stop | select-object -expandproperty DisplayName
                Write-Host -NoNewline "Current User name selected : "
                Write-Host "$UserFullName`n`n" -ForegroundColor Green
            } catch {
                # Write-Warning $_
                Write-Host "Hey dude, The user does NOT exist! check it again mate!" -ForegroundColor Red
                $NoUserExist = $true
            }
        }
    } While ($NoUserExist)

    # Write-Host "+------------------------------------------------------------------+"
    # Write-Host -NoNewline "Current User name selected : "
    # Write-Host "$UserFullName`n`n" -ForegroundColor Green
    # Write-Host "+------------------------------------------------------------------+"

    # 
    do {
        Write-Host "+------------------------------------------------------------------+"
        Write-Host -NoNewline "| User Name : "
        Write-Host "$UserFullName" -ForegroundColor Green
        Write-Host -NoNewline "| Email Box : "
        Write-Host "$EmailBoxName" -ForegroundColor Green
        Write-Host "+------------------------------------------------------------------+"
        Write-Host "|                 EMAIL DELEGATION OPERATION                       |"
        Write-Host "+------------------------------------------------------------------+"
        Write-Host "| [1] Add FullAccess  [2] Add SendAs  [3] Add Both (Full & SendAs) |"
        Write-Host "| [4] Del FullAccess  [5] Del SendAs  [6] Del Both (Full & SendAs) |"
        Write-Host "| [x] Quit Operation                                               |"
        Write-Host "+------------------------------------------------------------------+"
        $Access = Read-Host "Please select the access to grant or remove or [x] to exit"
        # $Granted = $true
        # $TryAgainAccess = $false
        $TryAgainAccess = $true

        Switch ($Access) {
            1 # Add Full Access
            { 
                $Granted = $true
                Write-Host "Adding Full access" -ForegroundColor DarkCyan
                try { Add-MailboxPermission $EmailBoxName -User $UserName -AccessRights FullAccess -InheritanceType All -ErrorAction Stop -WarningAction Stop | Out-Null } 
                catch { $Granted = $false }
                If ($Granted) { Write-Host "$UserFullName has granted Full Access to $EmailBoxAddress" -ForegroundColor Green }
            }
            2 # Add Send-As
            { 
                $Granted = $true
                Write-Host "Adding Send As access" -ForegroundColor DarkCyan
                try { Add-ADPermission -Identity $EmailBoxName -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop }
                catch { $Granted = $false }
                if ($Granted) { Write-Host "$UserFullName has granted Send As access to $EmailBoxAddress" -ForegroundColor Green}
            }
            3 # Add Both
            { 
                $AddedSendAs = $true
                Write-Host "Adding Send As access" -ForegroundColor DarkCyan
                try { Add-ADPermission -Identity $EmailBoxName -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop | Out-Null }
                catch { $AddedSendAs = $false }
                if ($AddedSendAs) { Write-Host "Send As access granted" -ForegroundColor Green }
                
                $AddedFull = $true
                Write-Host "Adding Full access" -ForegroundColor DarkCyan
                try { Add-MailboxPermission $EmailBoxName -User $UserName -AccessRights FullAccess -InheritanceType All -ErrorAction Stop -WarningAction Stop | Out-Null }
                catch { $AddedFull = $false }
                if ($AddedFull) { Write-Host "Full Access granted" -ForegroundColor Green }

                $Granted = $AddedSendAs -or $AddedFull # Generous Letter Service Policy
            }
            4 # Remove Full Access
            { 
                $Granted = $true
                Write-Host "Removing Full access" -ForegroundColor DarkCyan
                try { Remove-MailboxPermission $EmailBoxName -User $UserName -AccessRights FullAccess -InheritanceType All -ErrorAction Stop -WarningAction Stop | Out-Null }
                catch { $Granted = $false }
                if ($Granted) { Write-Host "$UserFullName has removed Full Access to $EmailBoxAddress" -ForegroundColor Green }
            }
            5 # Remove Send-As
            { 
                $Granted = $true
                Write-Host "Removing Send As access" -ForegroundColor DarkCyan
                try { Remove-ADPermission -Identity $EmailBoxName -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop }
                catch { $Granted = $false }
                if ($Granted) { Write-Host "$UserFullName has removed Send As access to $EmailBoxAddress" -ForegroundColor Green }
            }
            6 # Remove Both
            { 
                $RemovedSendAs = $true
                Write-Host "Removing Send As access" -ForegroundColor DarkCyan
                try { Remove-ADPermission -Identity $EmailBoxName -User $UserName -ExtendedRights "Send As" -ErrorAction Stop -WarningAction Stop }
                catch { $RemovedSendAs = $false }
                if ($RemovedSendAs) { Write-Host "Send As access removed!" -ForegroundColor Green}

                $RemovedFull = $true
                Write-Host "Removing Full access" -ForegroundColor DarkCyan
                try { Remove-MailboxPermission $EmailBoxName -User $UserName -AccessRights FullAccess -InheritanceType All -ErrorAction Stop -WarningAction Stop }
                catch { $RemovedFull = $false }
                if ($RemovedFull) { Write-Host "Full Access removed!" -ForegroundColor Green }

                $Granted = $RemovedSendAs -or $RemovedFull # Generous Letter Service Policy
            }
            'x' # x|X for Exit
            { 
                Write-Host "Exiting..." -ForegroundColor DarkGreen 
                $TryAgainAccess = $false
            }
            default 
            { 
                Write-Host "Wrong Selection. Try again"
                $TryAgainAccess = $true
            }
        }
        
        # Completion Letter Creation and Note
        if ($Access -match '[1-6]' -and $Granted) {
            # Letter Service
            $ConfirmLetter = Read-Host "Print a letter? (y/n)"
            if ($ConfirmLetter -ieq "y") {
                $Today = Get-Date -Format "dd-MMM-yyyy"
                $Header = "Dear Customer,"
                $AddBothAccess = "`r`nFull Access and Send As access has been provided to $UserFullName for mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
                $DelBothAccess = "`r`nFull Access and Send As access has been removed from $UserFullName for mailbox(s): $EmailBoxAddress.`n`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
                $AddFullAccess = "`r`n$UserFullName has been provided Full Access to mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
                $DelFullAccess = "`r`n$UserFullName has been removed Full Access from mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
                $AddSendAsAccess = "`r`n$UserFullName has been provided SendAs Access to mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
                $DelSendAsAccess = "`r`n$UserFullName has been removed SendAs Access from mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
                $Footer = "`r`nKind Regards,`r`n`r`nGovConnect Service Desk`r`nPhone: 1800 217 640`r`nPortal: https://portal.govconnect.nsw.gov.au"
                
                # Write-Host "= LETTER START =" -ForegroundColor Cyan
                <#
                Switch ($Access) {
                    1 { Write-Host $Header $AddFullAccess $Footer }
                    2 { Write-Host $Header $AddSendAsAccess $Footer }
                    3 { Write-Host $Header $AddBothAccess $Footer }
                    4 { Write-Host $Header $DelFullAccess $Footer }
                    5 { Write-Host $Header $DelSendAsAccess $Footer }
                    6 { Write-Host $Header $DelBothAccess $Footer }
                    default {Write-Host "Error"}
                }
                #>

                $Header | Out-File Letter.txt
                Switch ($Access) {
                    1 { $AddFullAccess | Out-File Letter.txt -Append }
                    2 { $AddSendAsAccess | Out-File Letter.txt -Append }
                    3 { $AddBothAccess | Out-File Letter.txt -Append }
                    4 { $DelFullAccess | Out-File Letter.txt -Append }
                    5 { $DelSendAsAccess | Out-File Letter.txt -Append }
                    6 { $DelBothAccess | Out-File Letter.txt -Append }
                    default {Write-Host "Error"}
                }
                $Footer | Out-File Letter.txt -Append
                Notepad Letter.txt
                Write-Host "Letter printed" -ForegroundColor Green
            }

            # Note Service
            $ConfirmNote = Read-Host "Write a note? (y/n)"
            if ($ConfirmNote -ieq "y") {
                $TicketNumber = Read-Host "Ticket Number please"
                $Today = Get-Date -Format "dd-MMM-yyyy"
                $Note = "Mailbox Access Provided: $TicketNumber / $Today"
                Write-Host "Note: $Note"
                $Info = Get-ADUser $UserName -Properties info | %{ $_.info}  
                Set-ADUser $UserName -Replace @{info="$($Info) `r`n $Note"}
                Write-Host "Note Added" -ForegroundColor Green
            } else {
                Write-Host "Note cancelled" -ForegroundColor DarkGreen
            }
        } elseif ($Access -ieq 'x') {
            # When selecting 'x'
            # Write-Host "Quit. No letter service" -ForegroundColor DarkGreen
        } else {
            Write-Host "Letter service cancelled due to access grant error" -ForegroundColor DarkGreen
        }
        
        
        if ($Access -eq 'x') {
            do {
                # Write-Host "+------------------------------------------------------------------+"
                Write-Host "+==================================================================+"
                Write-Host "|               Please Select Operation                            |"
                Write-Host "+==================================================================+"
                Write-Host "|  [1] Do other operation on the same user                         |"
                Write-Host "|  [2] Change user                                                 |"
                Write-Host "|  [3] Change Mailbox                                              |"
                Write-Host "|  [x] Quit Menu                                                   |"
                Write-Host "+==================================================================+"
                $Choice = Read-Host "What do you want?"

                switch ($Choice) {
                    1 
                    {
                        # Do other operation on the same user
                        $TryAgainAccess = $true
                    }
                    2
                    {
                        # Change user
                        $UserName = $false
                        $TryAgainAccess = $false
                        $ConfirmContinue = 'y'
                    }
                    3
                    {
                        # Change email box
                        $EmailBoxName = $false
                        $TryAgainAccess = $false
                        $ConfirmContinue = 'y'
                    }
                    'x'
                    {
                        # quit
                        Write-Host "Quiting..." -ForegroundColor DarkGreen
                        $TryAgainAccess = $false
                        $ConfirmContinue = 'n'

                    }
                    default 
                    { 
                        Write-Warning "Wrong Choice Bro! Select it again"
                        $Choice = $false
                    }
                }
            } while (!$Choice)
        }
        
    } while ($TryAgainAccess)

    if (!$ConfirmContinue -or $ConfirmContinue -ieq 'n') {
        $ConfirmContinue = Read-Host "Job finished. Try again?(y/n)"
        if ($ConfirmContinue -ieq 'y') {
            $EmailBoxName = $false
            $UserName = $false
            Clear-Host
            Write-Host $Logo -ForegroundColor Yellow
        }
    }

} while ($ConfirmContinue -ieq 'y')

#Close the PSSession
Get-PSSession | Remove-PSSession
Write-Host $Bye -ForegroundColor Yellow