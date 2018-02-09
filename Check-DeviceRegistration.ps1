# v1.1

[CmdletBinding()]
param ([string]$Identity)
."$PSScriptRoot\includes\functions.ps1"

function Write-Letter {
    param($Identity, $Registration)
    # $ConfirmLetter = Read-Host "Write a letter? (Y/n)"
    $ConfirmLetter = 'y'
    if ($ConfirmLetter -ieq 'y') {
        $UserName = Get-ADUser -Identity $Identity -Properties GivenName | Select-Object -ExpandProperty GivenName
        $YourName = (Get-ADUser $env:USERNAME).GivenName

        if ($Registration -ieq "MobileIron") {
            $Phrase = "email, calendar and contacts on your device"
            $PdfPath = "files\MOBILEIRON - Self-Help User Guide v1.7.pdf"

        } else {
            $Phrase = "to connect SFNET for remote access"
            $PdfPath = "files\AIRCARD - 4GX AirCard -Installation Guide v1.0.pdf"
        }

$Letter = "
Dear $UserName

This is just to notify that you are now registered for $Registration. 

Please find attached is the $Registration instruction which will guide you through to configure $Phrase.

Your first attempt may fail due to your account registration for $Registration is still in progress. Please allow 3-4 hours and try it again later.

If the problem persist or having any trouble configuring your device, please contact service desk or have your comments added on the GovConnectNSW portal and we will reopen the ticket.

Kind Regards,

$YourName
GovConnect Service Desk
Phone: 1800 217 640
Portal: https://portal.govconnect.nsw.gov.au 
"

        $Letter | Out-File Letter.txt
        Start-Process ((Resolve-Path "$pdfPath").Path)
        Notepad Letter.txt
    } else {
        Write-Host "Letter cancelled" -ForegroundColor DarkGreen
    }

}

function Write-Note {
    param ($Identity, $Registration)

    # $ConfirmNote = Read-Host "Write a note? (y/n)"
    $ConfirmNote = 'y'
    if ($ConfirmNote -ieq "y") {
        $TicketNumber = Read-Host "Ticket Number please"
        $Today = Get-Date -Format "dd-MMM-yyyy"
        $Note = "$Registration Provisioned: $TicketNumber / $Today"
        Write-Host "Note: $Note"
        $Info = Get-ADUser $Identity -Properties info | %{ $_.info}  
        Set-ADUser $Identity -Replace @{info="$($Info) `r`n $Note"}
        Write-Host "Note Added" -ForegroundColor Green
    } else {
        Write-Host "Note cancelled" -ForegroundColor DarkGreen
    }
}

function Show-Note {
    param ($Registration)

    if ($Registration -ieq "MobileIron") {
        # $Form = "Mobile Connection and Smartphone & Tablet form"
        # $CheckBox = "MobileIron (MDM) Required"
        # $Section = "SECTION 2a"
    } else {
        # $Form = "Mobile Connection and Smartphone & Tablet form"
        # $CheckBox = "Telstra Aircard"
        # $Section = "SECTION 3"
    }

    Write-Host "--------------------------------------------------------------"
    Write-Host "                            NOTE:" -ForegroundColor Magenta
    Write-Host "--------------------------------------------------------------"
    Write-Host " $Registration is now default security group/app to everyone."
    Write-Host " Please select 'Y' below to confirm to proceed the rego."
    # Write-Host " Please make sure that the user has provided a singed "
    # Write-Host -NoNewline " $Form" -ForegroundColor Yellow
    # Write-Host -NoNewline                            " and tick the box"
    # Write-Host " `"$CheckBox`""  -ForegroundColor Yellow
    # Write-Host " in the " -NoNewline
    # Write-Host "$Section." -ForegroundColor Green
    Write-Host "--------------------------------------------------------------"
}

function Add-Groups {
    param($Identity, $Groups)

    foreach ($Group in $Groups) {
        try {
            Add-ADGroupMember -Identity $Group -Members $Identity -ErrorAction Stop
            Write-Host -NoNewline "$Group"
            Write-Host " .....added" -ForegroundColor Green
            $Registered = $true
        } catch {
            Write-Host "$Group NOT added" -ForegroundColor Red
            Write-Warning $_
            # $Registered = $false
        }
    }
    return $Registered
}

function Show-Selection {
    Write-Host "========================================="
    Write-Host "          Mobility Checkup               " -BackGroundColor Black -ForegroundColor Green
    Write-Host "========================================="
    Write-Host -NonewLine " 1) Checking "
    Write-Host -NoNewLine "MobileIron "-ForegroundColor Yellow
    Write-Host "Registration"
    Write-Host -NoNewline " 2) Checking "
    Write-Host -NoNewLine "Aircard " -ForegroundColor Yellow
    Write-Host "Registration"
    Write-Host -NoNewline " 3) "
    Write-Host "Quit" -ForegroundColor Red
    Write-Host "========================================="
}

# Main function
function Check-Mobility { 

    param ($Identity, $Condition, $Registration, $MobileGroups)

    $UsrName = (Get-ADUser -Identity $Identity -Properties DisplayName).DisplayName

    if ($Condition) {
        Write-Host "Yes, $UsrName is a $Registration registered user" -ForegroundColor Green
    } else {
        Write-Host "No, $UsrName is NOT $Registration registered!" -ForegroundColor Red
        # $ConfirmRegister = Read-Host "Register? (Y/n)"
        # if ($ConfirmRegister -ieq 'y') {

            Show-Note -Registration $Registration
            <#
            if ($Registration -ieq "MobileIron") {
                Show-MINote
            } else {
                Show-ACNote
            }
            #>
            $ConfirmProceed = Read-Host "Confirm to proceed (Y/n)"
            if ($ConfirmProceed -ieq 'y') {
                $Registered = Add-Groups -Identity $Identity -Groups $MobileGroups
                if ($Registered) {
                    Write-Host "$UsrName has been registered successfully" -ForegroundColor Green
                    Write-Note -Identity $Identity -Registration $Registration
                    Write-Letter -Identity $Identity -Registration $Registration
                    Write-Host "Finished"
                } else {
                    Write-Host "$Registration registration for $UsrName has failed" -ForegroundColor Red
                }
            } else {
                Write-Host "Cancelled" -ForegroundColor Red
            }
        # } else {
        #     Write-Host "Cancelled" -ForegroundColor Red
        # }
    }
}

# Controller block
Clear-Host

# $console = $host.UI.RawUI
# $console.ForegroundColor = "black"
# $console.BackgroundColor = "white"

$MobileGroups = @("Mobility Authorised Users", "Mobility Email Exchange", "RES_AIRCARD_USER")
Show-Selection

do {
    $WrongSelection = $false
    $MenuSelection = Read-Host "Selection"

    switch ($MenuSelection) {
        1 {
            $Identity = Select-User -Identity $Identity
            $memberof = Get-ADUser -Identity $Identity -Properties MemberOf | Select-Object -ExpandProperty MemberOf -ErrorAction Stop
            $MobilityAuth = $memberof -imatch $MobileGroups[0]
            $MobilityMail = $memberof -imatch $MobileGroups[1]

            $Registration = "MobileIron"
            $Condition = ($MobilityAuth -and $MobilityMail)
            Check-Mobility -Identity $Identity -Condition $Condition -Registration $Registration -MobileGroups $MobileGroups[0..1]
        }
        2 {
            $Identity = Select-User -Identity $Identity
            $memberof = Get-ADUser -Identity $Identity -Properties MemberOf | Select-Object -ExpandProperty MemberOf -ErrorAction Stop
            $AircardReg = $memberof -imatch $MobileGroups[2]

            $Registration = "Aircard"
            $Condition = $AircardReg
            Check-Mobility -Identity $Identity -Condition $Condition -Registration $Registration -MobileGroups $MobileGroups[2]
        }
        3 {
            Write-Host "Exiting... Bye ^__^"
        }
        default {
            Write-Warning "Wrong selection. Try again."
            $WrongSelection = $true
            # $MenuSelection = $null
        }
    }

} while ($WrongSelection)