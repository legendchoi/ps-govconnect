<#
.DESCRIPTION
You must have your cn number and password encoded in the script before to use this script. 
You will have your cn number from eGuide - Meta.
#>

param (
    [Parameter()][string]$Uid
)

[System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null

. "$PSScriptRoot\includes\Functions.ps1"

Clear-Host
if (!$uid) {$uid = Read-host "Please provide the User ID"}
Write-Host "Connecting Exchange. Please wait..."
Get-ConnectExch

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
$yourOrgLevel1 =        $query.FindAll().properties['mUSRorgLevel1']
$yourOrgLevel2 =        $query.FindAll().properties['mUSRorgLevel2']
$yourOrgLevel3 =        $query.FindOne().properties['mUSRorgLevel3']
$yourOrgLevel4 =        $query.FindOne().properties['mUSRorgLevel4']
$yourPrimarySmtpAddress = (get-mailbox -Identity $uid | Select-Object PrimarySmtpAddress).PrimarySmtpAddress

# Check if the properties exist
$yourForgotPWEnableExist =  Test-PropertyExist -Uid $uid -PropertyName "mUSRaccountForgotPasswordEnabled" -ldapconnection $ldapentry
$yourForgotEmailExist =     Test-PropertyExist -Uid $uid -PropertyName "mUSRaccountForgotPasswordEmail" -ldapconnection $ldapentry
$yourEmailExist =           Test-PropertyExist -Uid $uid -PropertyName "mail" -ldapconnection $ldapentry
$yourSapEmailExist =        Test-PropertyExist -Uid $uid -PropertyName "mUSRAAsapmail" -ldapconnection $ldapentry
$yourSystemEmailAllExist =  Test-PropertyExist -Uid $uid -PropertyName "mUSRsystemMailAll" -ldapconnection $ldapentry
$yourPMMailExist =          Test-PropertyExist -Uid $uid -PropertyName "mUSRAApmmail" -ldapconnection $ldapentry
$yourADAliasExist =         Test-PropertyExist -Uid $uid -PropertyName "DirXML-ADAliasName" -ldapconnection $ldapentry


$Properties = @{
    DisplayName     = "$yourDisplayName"
    FullName        = "$yourfullName"
    SapID           = "$yourSAPID"
    WorkForceID     = "$yourWorkForceID"
    SystemWorkForceID = "$yourSysWorkForceID"
    SapWorkForceID  = "$yourSAPWorkForceID"
    Email           = "$yourEmail"
    SapEmail        = "$yourSapEmail"
    SystemEmailAll  = "$yourSystemEmailAll"
    PmMail          = "$yourPMMail"
    ADAlias         = "$yourADAlias"
    OrgUnit         = "$yourOrgUnit"
    OrgLevel1       = "$yourOrgLevel1"
    OrgLevel2       = "$yourOrgLevel2"
    OrgLevel3       = "$yourOrgLevel3"
    OrgLevel4       = "$yourOrgLevel4"
    ForgotPWEnable  = "$yourForgotPWEnable"
    ForgotEmail     = "$yourForgotEmail"
    ADManager       = "$yourADManager"
    SapManager      = "$yourSAPManager"
    PrimarySmtpAddress = "$yourPrimarySmtpAddress"
}

$User = New-Object -TypeName psobject -Property $Properties
$User | Format-List -Property SapId, OrgUnit, OrgLevel1, OrgLevel2, OrgLevel3, OrgLevel4, Email, SapEmail

$User | select -ExpandProperty DisplayName
$User | select -Property DisplayName

function Get-LdapEmails {
    param (
        $Identity,
        $LdapEntry
    )

    $uidfilter = "(uid=$Identity)"
    # $ldapentry = Get-LDAPConnectionEntry
    $q = New-Object System.DirectoryServices.DirectorySearcher($ldapentry,$uidfilter)
    $Email =            $q.FindOne().properties['mail']
    $SapEmail =         $q.FindOne().properties['mUSRAAsapmail']
    $SystemEmailAll =   $q.FindOne().properties['mUSRsystemMailAll']
    $PMMail =           $q.FindOne().properties['mUSRAApmmail']
    $ADAlias =          $q.FindOne().properties['DirXML-ADAliasName']

    $List = @(
        Mail = $Email
        
    )

    

    #
    #
}

function Get-LdapSapIDs {
    #
    #
}

function Get-LdapADManagers {
    #
    #
}

function Test-LdapForgotPasswordEmail {
    #
    #
}

function Set-LdapForgotPasswordEmail {
    #
    #
}

# Display Section
# SAP Related
Write-Host ""
Write-Output "Your Displyname is`t`t`t: $yourDisplayName"
Write-Output "Your Fullname is`t`t`t: $yourFullName"
Write-Host "Your CN is`t`t`t`t`t: $yourCN"
Write-Host ""
Write-Host "[SAP Related]" -ForegroundColor Yellow
Write-Host "Your SAP ID is`t`t`t`t: $yourSAPID"
Write-Host "Your WorkForceID is`t`t`t: $yourWorkForceID"
Write-Host "Your System WorkForceID is`t: $yourSysWorkForceID"
Write-Host "Your SAP WorkForce ID is`t: $yourSAPWorkForceID"
Write-Host "Your OrgUnit is`t`t`t`t: $yourOrgUnit" -BackgroundColor Red
# Email
Write-Host "[Email]" -ForegroundColor Yellow
Write-Host "Your Email from Exch is `t: $yourPrimarySmtpAddress"
Write-Host "Your Email is`t`t`t`t: $yourEmail $yourEmailExist"
Write-Host "Your SAP Email is `t`t`t: $yourSapEmail $yourSapEmailExist"
Write-Host "Your System Email All is`t: $yourSystemEmailAll $yourSystemEmailAllExist"
Write-Host "Your PM Mail is`t`t`t`t: $yourPMMail $yourPMMailExist"
Write-Host "Your AD Alias is`t`t`t: $yourADAlias $yourADAliasExist"


if ($yourPrimarySmtpAddress -ne $yourEmail) {
    Write-host "You have mismatch in Email addresses" -ForegroundColor Red
    $SyncEmail = Read-host "Do you want to sync them now? [y/n]"
    
    <# 
    Write-Host "Your SAP Email address`t`t: $yourSapEmail"
    if (($yourEmail -eq $null) -and ($yourSapEmail -ne $null)) {
        $yourEmail = $yourSapEmail
    }
    Write-Host "Your Email address`t`t`t: $yourEmail"
    #>
    
    if ($SyncEmail -ieq "y") {
        $ldapconnection = Get-LDAPConnection
        if ($yourEmailExist) {
            Set-LDAPUserProperty -UserCN $yourCN -ldapattrname "mail" -ldapattrvalue $yourPrimarySmtpAddress -ldapconnection $ldapconnection
        } else {
            Add-LDAPUserProperty -UserCN $yourCN -ldapattrname "mail" -ldapattrvalue $yourPrimarySmtpAddress -ldapconnection $ldapconnection
        }
        <#
        if ($yourForgotEmailExist) {
            Set-LDAPUserProperty -UserCN $yourCN -ldapattrname "mUSRaccountForgotPasswordEmail" -ldapattrvalue "$yourEmail" -ldapconnection $ldapconnection
        } else {
            Add-LDAPUserProperty -UserCN $yourCN -ldapattrname "mUSRaccountForgotPasswordEmail" -ldapattrvalue "$yourEmail" -ldapconnection $ldapconnection
        } 
        #>   
    } else {
        Write-Host "Job cancelled"
    }
}


<#
$yourPrimarySmtpAddress = (get-mailbox -Identity $uid | Select-Object PrimarySmtpAddress).PrimarySmtpAddress
$yourEmail =            $query.FindOne().properties['mail']
$yourSapEmail =         $query.FindOne().properties['mUSRAAsapmail']
$yourSystemEmailAll =   $query.FindOne().properties['mUSRsystemMailAll']
$yourPMMail =           $query.FindOne().properties['mUSRAApmmail']
$yourADAlias =          $query.FindOne().properties['DirXML-ADAliasName']

Write-Host "[Email]" -ForegroundColor Yellow
Write-Host "Your Email from Exch is `t: $yourPrimarySmtpAddress"
Write-Host "Your Email is`t`t`t`t: $yourEmail $yourEmailExist"
Write-Host "Your SAP Email is `t`t`t: $yourSapEmail $yourSapEmailExist"
Write-Host "Your System Email All is`t: $yourSystemEmailAll $yourSystemEmailAllExist"
Write-Host "Your PM Mail is`t`t`t`t: $yourPMMail $yourPMMailExist"
Write-Host "Your AD Alias is`t`t`t: $yourADAlias $yourADAliasExist"
#>



# Forgot Password
Write-Host "[Forgot Password]" -ForegroundColor Yellow
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
Write-Host "[Manager]" -ForegroundColor Yellow
if ($yourADManager -ne $null) {
    $yourADManager = $yourADManager -replace '^CN=|,.*$'
    $yourADManager = Convert-CNToUID -cn $yourADManager -ldapconnection $ldapentry
    $yourADManagerFullName = Get-ADUser $yourADManager -Properties displayname | Select-Object -ExpandProperty displayname
    $yourADManagerEmail = Get-ADUser $yourADManager -Properties userprincipalname | Select-Object -ExpandProperty userprincipalname
    Write-Host "Your AD Manager is`t`t`t: $yourADManagerFullName($yourADManager) - $yourADManagerEmail"
} else {
    Write-Host -nonewline "Your AD Manager is`t`t`t: "
    Write-Host "No ADManager is set" -ForegroundColor red
}

# Search SAP Manager
if ($yourSAPManager -ne $null) {
    $yourSAPManager = $yourSAPManager -replace '^CN=|,.*$' 
    $yourSAPManager = Convert-CNToUID -cn $yourSAPManager -ldapconnection $ldapentry
    $yourSAPManagerFullName = Get-ADUser $yourSAPManager -Properties displayname | Select-Object -ExpandProperty displayname
    $yourSAPManagerEmail = Get-ADUser $yourSAPManager -Properties userprincipalname | Select-Object -ExpandProperty userprincipalname
    Write-Host "Your SAP Manager is`t`t`t: $yourSAPManagerFullName($yourSAPManager) - $yourSAPManagerEmail"
} else {
    Write-Host -nonewline "Your SAP Manager is`t`t`t: "
    Write-Host "No SAP Manager is set" -ForegroundColor red
}



# Tested with user MAHMOODS
# $ldapconnection = Get-LDAPConnection
# Add-LDAPUserProperty -UserCN "GIS7207" -LdapAttrName "mail" -ldapattrvalue "Syed.Mahmood@finance.nsw.gov.au" -ldapconnection $ldapconnection

# $ldapconnection = Get-LDAPConnection
# Set-LDAPUserProperty -UserCN "TSR6602" -LdapAttrName "mUSRsystemMailAll" -ldapattrvalue "hyun.choi@govconnect.nsw.gov.au" -ldapconnection $ldapconnection
# Set-LDAPUserProperty -UserCN "TSR6602" -LdapAttrName "mUSRAApmmail" -ldapattrvalue "hyun.choi@govconnect.nsw.gov.au" -ldapconnection $ldapconnection
# 'mail' attribute made change the value at Exchange, eGuide and AD user property synced all except IDM - Modify Email Address
<#
DirXML-ADAliasName	hyun.choi@govconnect.nsw.gov.au
mail	hyun.choi@govconnect.nsw.gov.au
mUSRAApmmail	Hyun.Choi@servicefirst.nsw.gov.au
mUSRsystemMailAll	Hyun.Choi@servicefirst.nsw.gov.au (idm: refering modify email)
*** when click 'submit' in modifying email - sapemail attribute was created


# mail
# DirXML-ADAliasName
# mUSRAApmmail
# mUSRsystemMailAll
# mUSRAAsapmail

Set-LDAPUserProperty -UserCN "TSR6602" -LdapAttrName "mail" -ldapattrvalue "hyun.choi@govconnect.nsw.gov.au" -ldapconnection $ldapconnection
#>

# Test Busienss Logic
<#
$targetuserdn = "cn=$yourcn,$basedn"
$ldapconnection = Get-LDAPConnection
$ldapattrname = "mUSRaccountForgotPasswordEmail"
# $ldapattrname = "somerandomeattr"
$ldapattrvalue = "test.test222@hotmail.com"
Add-LDAPUserProperty -targetuserdn $targetuserdn -ldapattrname $ldapattrname -ldapattrvalue $ldapattrvalue -ldapconnection $ldapconnection
#>

<# 
LDAP Properties

FORGOT PASSWORD
# mUSRaccountForgotPasswordEmail
# mUSRaccountForgotPasswordEnabled = ["TRUE"|"FALSE"]

SAP
# DirXML-sapPID
# workforceID
# mUSRsystemWorkforceID
# mUSRAApmworkforceID

EMAIL
# mail
# DirXML-ADAliasName
# mUSRAApmmail
# mUSRsystemMailAll

Password Reset
# cn=PasswordAdministration,cn=RequestDefs,cn=AppConfig,cn=UserApplication,cn=DriverSet,ou=idm,o=services

# Update Email Address
<input type="hidden" name="value(apwaDetailId)" value="cn=UpdateEmailAddress,cn=RequestDefs,cn=AppConfig,cn=UserApplication,cn=DriverSet,ou=idm,o=services" id="apwaDetailId"/><
modifiersName	cn=dc1lmeta01,o=services

#>