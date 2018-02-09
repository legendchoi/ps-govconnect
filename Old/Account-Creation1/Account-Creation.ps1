<#
.DESCRIPTION
Mun I hate you! You give me so much jobs to do!
#>

param ([CmdletBinding()][Parameter()][string]$UID)

[System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null

# . "$PSScriptRoot\includes\Functions.ps1"
# . "$PSScriptRoot\includes\Letter-Service.ps1"
# . "$PSScriptRoot\includes\DeptTable.ps1"
. "$PSScriptRoot\New-ADUser1.0.ps1"
# . "$PSScriptRoot\Non-ITClient.ps1"


function Get-LDAPUserDetail {
    param ($Identity)

    $uid = "(uid=$Identity)"
    $ldapentry = Get-LDAPConnectionEntry
    $query = New-Object System.DirectoryServices.DirectorySearcher($ldapentry,$uid)

    $CN = Convert-UIDToCN -uid $Identity -ldapconnection $ldapentry
    $DisplayName =      $query.FindOne().properties['displayName']
    $FullName =         $query.FindOne().properties['fullName']
    $SAPID =            $query.FindOne().properties['DirXML-sapPID']
    $WorkForceID =      $query.FindOne().properties['workforceID']
    $SysWorkForceID =   $query.FindOne().properties['mUSRsystemWorkforceID']
    $SAPWorkForceID =   $query.FindOne().properties['mUSRAApmworkforceID']
    $Email =            $query.FindOne().properties['mail']
    $SapEmail =         $query.FindOne().properties['mUSRAAsapmail']
    $SystemEmailAll =   $query.FindOne().properties['mUSRsystemMailAll']
    $PMMail =           $query.FindOne().properties['mUSRAApmmail']
    $ADAlias =          $query.FindOne().properties['DirXML-ADAliasName']
    $OrgUnit =          $query.FindOne().properties['dirxml-sapp-a-o']
    $ForgotPWEnable =   $query.FindOne().properties['mUSRaccountForgotPasswordEnabled']
    $ForgotEmail =      $query.FindOne().properties['mUSRaccountForgotPasswordEmail']
    $ADManager =        $query.FindOne().properties['manager']
    $SAPManager =       $query.FindOne().properties['musraapmmanager']
    $OrgLevel1 =       $query.FindOne().properties['mUSRorgLevel1']
    $OrgLevel2 =       $query.FindOne().properties['mUSRorgLevel2']
    $OrgLevel3 =       $query.FindOne().properties['mUSRorgLevel3']
    $OrgLevel4 =       $query.FindOne().properties['mUSRorgLevel4']

    # Check if the properties exist
    $ForgotPWEnableExist =  Test-PropertyExist -Uid $Identity -PropertyName "mUSRaccountForgotPasswordEnabled" -ldapconnection $ldapentry
    $ForgotEmailExist =     Test-PropertyExist -Uid $Identity -PropertyName "mUSRaccountForgotPasswordEmail" -ldapconnection $ldapentry
    $EmailExist =           Test-PropertyExist -Uid $Identity -PropertyName "mail" -ldapconnection $ldapentry
    $SapEmailExist =        Test-PropertyExist -Uid $Identity -PropertyName "mUSRAAsapmail" -ldapconnection $ldapentry
    $SystemEmailAllExist =  Test-PropertyExist -Uid $Identity -PropertyName "mUSRsystemMailAll" -ldapconnection $ldapentry
    $PMMailExist =          Test-PropertyExist -Uid $Identity -PropertyName "mUSRAApmmail" -ldapconnection $ldapentry
    $ADAliasExist =         Test-PropertyExist -Uid $Identity -PropertyName "DirXML-ADAliasName" -ldapconnection $ldapentry


    # SAP Related
    Write-Host ""
    Write-Output "Your Displyname is`t`t`t: $DisplayName"
    # Write-Output "Your Fullname is`t`t`t: $yourFullName"
    # Write-Host "Your CN is`t`t`t`t`t: $yourCN"
    # Write-Host ""
    # Write-Host "[SAP Related]" -ForegroundColor Yellow
    Write-Host "Your SAP ID is`t`t`t`t: $SAPID"
    # Write-Host "Your WorkForceID is`t`t`t: $yourWorkForceID"
    # Write-Host "Your System WorkForceID is`t: $yourSysWorkForceID"
    # Write-Host "Your SAP WorkForce ID is`t: $yourSAPWorkForceID"
    # Write-Host "[Org Related]" -ForegroundColor Yellow
    Write-Host -NoNewline "Your OrgUnit is`t`t`t`t: "
    Write-Host "$OrgUnit" -BackgroundColor Red
    Write-Host "Your Org Level 1 is `t`t: $OrgLevel1"
    Write-Host "Your Org Level 2 is `t`t: $OrgLevel2"
    Write-Host "Your Org Level 1 is `t`t: $OrgLevel3"
    Write-Host "Your Org Level 2 is `t`t: $OrgLevel4"
    # Write-Host "[Email]" -ForegroundColor Yellow
    Write-Host "Your Email is`t`t`t`t: $Email $EmailExist"
    Write-Host "Your SAP Email is `t`t`t: $SapEmail $SapEmailExist"
    # Write-Host "Your System Email All is`t: $yourSystemEmailAll $yourSystemEmailAllExist"
    # Write-Host "Your PM Mail is`t`t`t`t: $yourPMMail $yourPMMailExist"
    # Write-Host "Your AD Alias is`t`t`t: $yourADAlias $yourADAliasExist"
}

function New-NonITClient {
    param (
        $ReferenceUser,
        $TargetUser,
        $TargetUserSAPID,
        $TargetUserEmail
    )

    $ReferenceUserName = Get-ADUser $ReferenceUser -Properties DisplayName | Select-Object -ExpandProperty DisplayName
    $TargetUserName = Get-ADUser $TargetUser -Properties DisplayName | Select-Object -ExpandProperty DisplayName

    Clear-Host
    Write-Host "Non-IT Clients Account Creation" -ForegroundColor Magenta

    Write-Host "`r`n+----------------------------------------------------+"
    Write-Host -NoNewline "|  Referece User : "
    Write-Host "$ReferenceUserName" -ForegroundColor Green
    Write-Host -NoNewline "|  Target User   : "
    Write-Host "$TargetUserName" -ForegroundColor Green
    Write-Host "+----------------------------------------------------+"
    Write-Host "|  The script will run through the steps below.      |"
    Write-Host "+----------------------------------------------------+"
    Write-Host "|  STEP 1: Printing user detail letter               |"
    Write-Host "|  STEP 2: Writing Note on Telephone tab             |"
    Write-Host "+----------------------------------------------------+"
    $ConfirmFirst = Read-Host "Press [ENTER] key to continue or [x] to Exit"
    if ($ConfirmFirst -ine 'x') {
        Write-Host "Please, provide the password to produce a letter"
        $PW = Read-Host "Password"
        $SAPID = 
        $EmailAddress = 
        $letter = Get-LetterNewUser -Identity $TargetUser -Manager $ReferenceUser -Password $PW -SAPID $yourSAPID -Email $yourEmail
        $letter | Out-File Letter-NonIT.txt
        Notepad Letter-NonIT.txt
        Write-Host "Letter printed" -ForegroundColor Green
        Write-Note -Identity $uid -Option 1
    } else {
        Write-Host "Exit"
    }
}


Clear-Host
$Handsome = (Get-ADUser $env:USERNAME).GivenName
Write-Host "+================================+"
Write-Host "   Account Creation PowerScript   " -BackgroundColor Blue
Write-Host "   Hello, $Handsome"
Write-Host "+================================+"

if (!$UID) {$UID = Read-host "Please provide the new User ID"}
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
$yourOrgLevel1 =       $query.FindOne().properties['mUSRorgLevel1']
$yourOrgLevel2 =       $query.FindOne().properties['mUSRorgLevel2']
$yourOrgLevel3 =       $query.FindOne().properties['mUSRorgLevel3']
$yourOrgLevel4 =       $query.FindOne().properties['mUSRorgLevel4']

# Check if the properties exist
$yourForgotPWEnableExist =  Test-PropertyExist -Uid $uid -PropertyName "mUSRaccountForgotPasswordEnabled" -ldapconnection $ldapentry
$yourForgotEmailExist =     Test-PropertyExist -Uid $uid -PropertyName "mUSRaccountForgotPasswordEmail" -ldapconnection $ldapentry
$yourEmailExist =           Test-PropertyExist -Uid $uid -PropertyName "mail" -ldapconnection $ldapentry
$yourSapEmailExist =        Test-PropertyExist -Uid $uid -PropertyName "mUSRAAsapmail" -ldapconnection $ldapentry
$yourSystemEmailAllExist =  Test-PropertyExist -Uid $uid -PropertyName "mUSRsystemMailAll" -ldapconnection $ldapentry
$yourPMMailExist =          Test-PropertyExist -Uid $uid -PropertyName "mUSRAApmmail" -ldapconnection $ldapentry
$yourADAliasExist =         Test-PropertyExist -Uid $uid -PropertyName "DirXML-ADAliasName" -ldapconnection $ldapentry


# SAP Related
Write-Host ""
Write-Output "Your Displyname is`t`t`t: $yourDisplayName"
# Write-Output "Your Fullname is`t`t`t: $yourFullName"
# Write-Host "Your CN is`t`t`t`t`t: $yourCN"
# Write-Host ""
# Write-Host "[SAP Related]" -ForegroundColor Yellow
Write-Host "Your SAP ID is`t`t`t`t: $yourSAPID"
# Write-Host "Your WorkForceID is`t`t`t: $yourWorkForceID"
# Write-Host "Your System WorkForceID is`t: $yourSysWorkForceID"
# Write-Host "Your SAP WorkForce ID is`t: $yourSAPWorkForceID"
# Write-Host "[Org Related]" -ForegroundColor Yellow
Write-Host -NoNewline "Your OrgUnit is`t`t`t`t: "
Write-Host "$yourOrgUnit" -BackgroundColor Red
Write-Host "Your Org Level 1 is `t`t: $yourOrgLevel1"
Write-Host "Your Org Level 2 is `t`t: $yourOrgLevel2"
Write-Host "Your Org Level 1 is `t`t: $yourOrgLevel3"
Write-Host "Your Org Level 2 is `t`t: $yourOrgLevel4"
# Write-Host "[Email]" -ForegroundColor Yellow
Write-Host "Your Email is`t`t`t`t: $yourEmail $yourEmailExist"
Write-Host "Your SAP Email is `t`t`t: $yourSapEmail $yourSapEmailExist"
# Write-Host "Your System Email All is`t: $yourSystemEmailAll $yourSystemEmailAllExist"
# Write-Host "Your PM Mail is`t`t`t`t: $yourPMMail $yourPMMailExist"
# Write-Host "Your AD Alias is`t`t`t: $yourADAlias $yourADAliasExist"
# Write-Host "[Forgot Password]" -ForegroundColor Yellow
Write-Host "Your Forgot PW Enable is`t: $yourForgotPWEnable $yourForgotPWEnableExist"
Write-Host "Your Forgot Email is`t`t: $yourForgotEmail $yourForgotEmailExist"

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

# Search AD Manager
# Write-Host "[Manager]" -ForegroundColor Yellow
Write-Host -NoNewline "Your AD Manager is`t`t`t: "
if ($yourADManager -ne $null) {
    $yourADManager = $yourADManager -replace '^CN=|,.*$'
    $yourADManager = Convert-CNToUID -cn $yourADManager -ldapconnection $ldapentry
    $yourADManagerFullName = Get-ADUser $yourADManager -Properties displayname | Select-Object -ExpandProperty displayname
    $yourADManagerEmail = Get-ADUser $yourADManager -Properties userprincipalname | Select-Object -ExpandProperty userprincipalname
    Write-Host "$yourADManagerFullName($yourADManager) - $yourADManagerEmail"
} else {
    Write-Host "No ADManager is set" -ForegroundColor Red
}

# Search SAP Manager
Write-Host -NoNewline "Your SAP Manager is`t`t`t: "
if ($yourSAPManager -ne $null) {
    $yourSAPManager = $yourSAPManager -replace '^CN=|,.*$' 
    $yourSAPManager = Convert-CNToUID -cn $yourSAPManager -ldapconnection $ldapentry
    $yourSAPManagerFullName = Get-ADUser $yourSAPManager -Properties displayname | Select-Object -ExpandProperty displayname
    $yourSAPManagerEmail = Get-ADUser $yourSAPManager -Properties userprincipalname | Select-Object -ExpandProperty userprincipalname
    Write-Host "$yourSAPManagerFullName($yourSAPManager) - $yourSAPManagerEmail"
} else {
    Write-Host "No SAP Manager is set" -ForegroundColor Red
}

# write-host $yourADManager

if ($yourADManager -ne $null) {
    $ConfirmManager = Read-Host "Is the manager correct? (y/n)"
    $yourADManagerDisplayName = $yourADManagerFullName
} else {

    $ConfirmManager ='n'
}

Write-host "Please provide the manger name below" -ForegroundColor Yellow
if ($ConfirmManager -ine 'y') {
    $yourADManager = Select-User
    $yourADManagerDisplayName = Get-ADUser $yourADManager -Properties displayname | Select-Object -ExpandProperty displayname
}

Get-LDAPUserDetail -Identity $yourADManager

Write-Host "+================================================+"
Write-Host "|  Reference User   : $yourADManagerDisplayName"
write-Host "|  Target User      : $yourDisplayName"
#    Clear-Host
Write-Host "+===============================================+"
Write-Host "|        SUB MENU: Account Creation for         |"
Write-Host "+===============================================+"
Write-Host "|   [1] IT Clients                              |"
Write-Host "|   [2] Non-IT Clients                          |"
Write-Host "|   [x] Quit                                    |"
Write-Host "+===============================================+"

do {
    $accountselection = Read-Host "Your section"
    $wrongchoice = $false
    if ($accountselection -ieq '1') {
        #IT Clients
        New-ADUser -ReferenceUser $yourADManager -TargetUser $UID
    } elseif ($accountselection -ieq '2') {
        #Non-IT Clients
        New-NonITClient -ReferenceUser $yourADManager -TargetUser $UID -TargetUserSAPID $yourSAPID -TargetUserEmail $yourEmail
    } elseif ($accountselection -ine 'x') {
        Write-Host "Wrong Choice. Try again" -ForegroundColor Red
        $wrongchoice = $true
    }
} while ($wrongchoice)
