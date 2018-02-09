# v1.3

# Parameter
param ([CmdletBinding()][Parameter()][string]$UID)

# Assembly
[System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null

# Include
. "$PSScriptRoot\New-ADUser1.1.ps1"

# Main
Clear-Host
$Handsome = (Get-ADUser $env:USERNAME).GivenName
Write-Host "====================================================================================="
Write-Host "                        Account Creation PowerScript                                 " -BackgroundColor Blue
Write-Host "                            Hello, $Handsome"
Write-Host "====================================================================================="

if (!$UID) {
    $userid = Read-Host "Please provide the new user's name or ID"
    $UID = Select-User $userid
    $yourDisplayName = (Get-ADUser -Identity $UID -Properties DisplayName).DisplayName
}

Get-LDAPUserDetail -Identity $UID -IsManager $false





if ($yourADManager -ne $null) {
    $ConfirmManager = Read-Host "Is the manager correct? (y/n)"
    $yourADManagerDisplayName = $yourADManagerFullName
} else {
    $ConfirmManager ='n'
}



$managerid = Read-host "`nPlease provide the manager name or ID"
if ($ConfirmManager -ine 'y') {
    $yourADManager = Select-User $managerid
    $yourADManagerDisplayName = Get-ADUser $yourADManager -Properties displayname | Select-Object -ExpandProperty displayname
}
Get-LDAPUserDetail -Identity $yourADManager -IsManager $true



Write-Host "`n`n"
Write-Host "====================================================================================="
Write-Host "Reference User   : $yourADManagerDisplayName"
write-Host "Target User      : $yourDisplayName"
Write-Host "====================================================================================="
Write-Host "|                       SUB MENU: Account Creation for                              |"
Write-Host "====================================================================================="
Write-Host "|   [1] IT Clients                                                                  |"
Write-Host "|   [2] Non-IT Clients                                                              |"
Write-Host "|   [x] Quit                                                                        |"
Write-Host "====================================================================================="

do {
    $accountselection = Read-Host "Your section"
    $wrongchoice = $false

    switch ($accountselection) {
        1 { New-ADUser -ReferenceUser $yourADManager -TargetUser $UID }
        2 { New-NonITClient -ReferenceUser $yourADManager -TargetUser $UID }
        'x' {}
        default { Write-Host "Wrong Choice. Try again" -ForegroundColor Red; $wrongchoice = $true }
    }
} while ($wrongchoice)
