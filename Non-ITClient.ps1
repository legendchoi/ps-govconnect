<#
.DESCRIPTION
You must have your cn number and password encoded in the script before to use this script. 
You will have your cn number from eGuide - Meta.
#>

param ([CmdletBinding()][Parameter()][string]$UID)

[System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null

. "$PSScriptRoot\includes\Functions.ps1"
. "$PSScriptRoot\includes\Letter-Service.ps1"


if (!$UID) {$UID = Read-host "Please provide the User ID"}
$uidfilter = "(uid=$uid)"
$ldapentry = Get-LDAPConnectionEntry
$query = New-Object System.DirectoryServices.DirectorySearcher($ldapentry,$uidfilter)

$yourCN = Convert-UIDToCN -uid $uid -ldapconnection $ldapentry
$yourDisplayName =      $query.FindOne().properties['displayName']
$yourfullName =         $query.FindOne().properties['fullName']
$yourSAPID =            $query.FindOne().properties['DirXML-sapPID']
$yourWorkForceID =      $query.FindOne().properties['workforceID']
$yourSysWorkForceID =   $query.FindOne().properties['mUSRsystemWorkforceID']
$yourSAPWorkForceID =   $query.FindOne().properties['mUSRAApmworkforceID']
$yourEmail =            $query.FindOne().properties['mail']
$yourSapEmail =         $query.FindOne().properties['mUSRAAsapmail']
$yourSystemEmailAll =   $query.FindOne().properties['mUSRsystemMailAll']
$yourPMMail =           $query.FindOne().properties['mUSRAApmmail']
$yourADAlias =          $query.FindOne().properties['DirXML-ADAliasName']
$yourOrgUnit =          $query.FindOne().properties['dirxml-sapp-a-o']
$yourForgotPWEnable =   $query.FindOne().properties['mUSRaccountForgotPasswordEnabled']
$yourForgotEmail =      $query.FindOne().properties['mUSRaccountForgotPasswordEmail']
$yourADManager =        $query.FindOne().properties['manager']
$yourSAPManager =       $query.FindOne().properties['musraapmmanager']

# Check if the properties exist
$yourForgotPWEnableExist =  Test-PropertyExist -Uid $uid -PropertyName "mUSRaccountForgotPasswordEnabled" -ldapconnection $ldapentry
$yourForgotEmailExist =     Test-PropertyExist -Uid $uid -PropertyName "mUSRaccountForgotPasswordEmail" -ldapconnection $ldapentry
$yourEmailExist =           Test-PropertyExist -Uid $uid -PropertyName "mail" -ldapconnection $ldapentry
$yourSapEmailExist =        Test-PropertyExist -Uid $uid -PropertyName "mUSRAAsapmail" -ldapconnection $ldapentry
$yourSystemEmailAllExist =  Test-PropertyExist -Uid $uid -PropertyName "mUSRsystemMailAll" -ldapconnection $ldapentry
$yourPMMailExist =          Test-PropertyExist -Uid $uid -PropertyName "mUSRAApmmail" -ldapconnection $ldapentry
$yourADAliasExist =         Test-PropertyExist -Uid $uid -PropertyName "DirXML-ADAliasName" -ldapconnection $ldapentry


# Display Section
# SAP Related
Write-Host ""
Write-Output "Your Displyname is`t`t`t: $yourDisplayName"
Write-Output "Your Fullname is`t`t`t: $yourFullName"
# Write-Host "Your CN is`t`t`t`t`t: $yourCN"
Write-Host ""
Write-Host "[SAP Related]" -ForegroundColor Yellow
Write-Host "Your SAP ID is`t`t`t`t: $yourSAPID"
# Write-Host "Your WorkForceID is`t`t`t: $yourWorkForceID"
# Write-Host "Your System WorkForceID is`t: $yourSysWorkForceID"
# Write-Host "Your SAP WorkForce ID is`t: $yourSAPWorkForceID"
# Write-Host "Your OrgUnit is`t`t`t`t: $yourOrgUnit" -BackgroundColor Red
# Email
Write-Host "[Email]" -ForegroundColor Yellow
Write-Host "Your Email is`t`t`t`t: $yourEmail $yourEmailExist"
Write-Host "Your SAP Email is `t`t`t: $yourSapEmail $yourSapEmailExist"
# Write-Host "Your System Email All is`t: $yourSystemEmailAll $yourSystemEmailAllExist"
# Write-Host "Your PM Mail is`t`t`t`t: $yourPMMail $yourPMMailExist"
# Write-Host "Your AD Alias is`t`t`t: $yourADAlias $yourADAliasExist"
# Forgot Password
Write-Host "[Forgot Password]" -ForegroundColor Yellow
Write-Host "Your Forgot PW Enable is`t: $yourForgotPWEnable $yourForgotPWEnableExist"
Write-Host "Your Forgot Email is`t`t: $yourForgotEmail $yourForgotEmailExist"


# Search AD Manager
Write-Host "[Manager]" -ForegroundColor Yellow
if ($yourADManager -ne $null) {
    $yourADManager = $yourADManager -replace '^CN=|,.*$'
    $yourADManager = Convert-CNToUID -cn $yourADManager -ldapconnection $ldapentry
    $yourADManagerFullName = Get-ADUser $yourADManager -Properties displayname | Select-Object -ExpandProperty displayname
    $yourADManagerEmail = Get-ADUser $yourADManager -Properties userprincipalname | Select-Object -ExpandProperty userprincipalname
    Write-Host "Your AD Manager is`t`t`t: $yourADManagerFullName($yourADManager) - $yourADManagerEmail"
} else {
    Write-Host "No ADManager is set" -ForegroundColor Red
}

# Search SAP Manager
if ($yourSAPManager -ne $null) {
    $yourSAPManager = $yourSAPManager -replace '^CN=|,.*$' 
    $yourSAPManager = Convert-CNToUID -cn $yourSAPManager -ldapconnection $ldapentry
    $yourSAPManagerFullName = Get-ADUser $yourSAPManager -Properties displayname | Select-Object -ExpandProperty displayname
    $yourSAPManagerEmail = Get-ADUser $yourSAPManager -Properties userprincipalname | Select-Object -ExpandProperty userprincipalname
    Write-Host "Your SAP Manager is`t`t`t: $yourSAPManagerFullName($yourSAPManager) - $yourSAPManagerEmail"
} else {
    Write-Host "No SAP Manager is set" -ForegroundColor Red
}

# Setup 'Forget Password Email' for a user whose email is provided but no 'Forget Password Email' has been enabled.
if ( ($yourEmail -ne $null -or $yourSapEmail -ne $null) -and ($yourForgotPWEnableExist -eq $false -or $yourForgotEmailExist -eq $false)) {
    Write-Warning "You have not set Forgot Password Email"
    $ConfirmForgetPWEmail = Read-host "Do you want to set it now? [y/n]"
    
    <# 
    Write-Host "Your SAP Email address`t`t: $yourSapEmail"
    if (($yourEmail -eq $null) -and ($yourSapEmail -ne $null)) {
        $yourEmail = $yourSapEmail
    }
    Write-Host "Your Email address`t`t`t: $yourEmail"
    #>
    
    if ($ConfirmForgetPWEmail -ieq "y") {
        $ldapconnection = Get-LDAPConnection
        if ($yourForgotPWEnableExist) {
            Set-LDAPUserProperty -UserCN $yourCN -ldapattrname "mUSRaccountForgotPasswordEnabled" -ldapattrvalue "TRUE" -ldapconnection $ldapconnection
        } else {
            Add-LDAPUserProperty -UserCN $yourCN -ldapattrname "mUSRaccountForgotPasswordEnabled" -ldapattrvalue "TRUE" -ldapconnection $ldapconnection
        }
        if ($yourForgotEmailExist) {
            Set-LDAPUserProperty -UserCN $yourCN -ldapattrname "mUSRaccountForgotPasswordEmail" -ldapattrvalue "$yourEmail" -ldapconnection $ldapconnection
        } else {
            Add-LDAPUserProperty -UserCN $yourCN -ldapattrname "mUSRaccountForgotPasswordEmail" -ldapattrvalue "$yourEmail" -ldapconnection $ldapconnection
        }    
    } else {
        Write-Host "Job cancelled"
    }
}

# write-host $yourADManager

if ($yourADManager -ne $null) {
    $ConfirmManager = Read-Host "Is the manager correct? (y/n)"
} else {
    $ConfirmManager ='n'
}

Write-host "Manger Name" -ForegroundColor Yellow
if ($ConfirmManager -ine 'y') {
    $yourADManager = Select-User
}

$PW = Read-Host "What's Password"
$letter = Get-LetterNewUser -Identity $uid -Manager $yourADManager -Password $PW -SAPID $yourSAPID -Email $yourEmail
$letter | Out-File Letter-NonIT.txt
Notepad Letter-NonIT.txt
Write-Host "Letter printed" -ForegroundColor Green

$ConfirmNote = Read-Host "Write a note in $yourfullName's Telephone Tab? (y/n)"
if ($ConfirmNote -ieq "y") {
    $TicketNo = Read-Host "What's Ticket Number"
    $today = Get-date -Format "dd-MMM-yyy"
    $Note = "Account Provision Request: $TicketNo /$today"
    $Note
    $Info = Get-ADUser $UID -Properties info | ForEach-Object{ $_.info}
    try {
        Set-ADUser $UID -Replace @{info="$($Info) `r`n $Note"} -ErrorAction Stop
        Write-Host "Note Added" -ForegroundColor Green
    } catch {
        Write-Error $_
    }            
}