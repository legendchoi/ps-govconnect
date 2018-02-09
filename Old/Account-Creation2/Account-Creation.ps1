# v1.2

# Parameter
param ([CmdletBinding()][Parameter()][string]$UID)

# Assembly
[System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null

# Include
. "$PSScriptRoot\New-ADUser1.1.ps1"

# New-Account 
function Set-ForgotPasswordEmail {
    param ($Identity)

    $uid = "(uid=$Identity)"
    $ldapentry = Get-LDAPConnectionEntry
    $query = New-Object System.DirectoryServices.DirectorySearcher($ldapentry,$uid)
    $CN = Convert-UIDToCN -uid $Identity -ldapconnection $ldapentry

    $Email =            $query.FindOne().properties['mail']
    $SapEmail =         $query.FindOne().properties['mUSRAAsapmail']
    $ForgotPWEnable =   $query.FindOne().properties['mUSRaccountForgotPasswordEnabled']
    $ForgotEmail =      $query.FindOne().properties['mUSRaccountForgotPasswordEmail']

    $ForgotPWEnableExist =  Test-PropertyExist -Uid $Identity -PropertyName "mUSRaccountForgotPasswordEnabled" -ldapconnection $ldapentry
    $ForgotEmailExist =     Test-PropertyExist -Uid $Identity -PropertyName "mUSRaccountForgotPasswordEmail" -ldapconnection $ldapentry

    Write-Host "Your Forgot PW Enable is`t: $ForgotPWEnable $ForgotPWEnableExist"
    Write-Host "Your Forgot Email is`t`t: $ForgotEmail $ForgotEmailExist"

    # Setup 'Forget Password Email' for a user whose email is provided but no 'Forget Password Email' has been enabled.
    if ( ($Email -ne $null -or $SapEmail -ne $null) -and ($ForgotPWEnableExist -eq $false -or $ForgotEmailExist -eq $false)) {
        Write-Warning "You have not set Forgot Password Email"
        $ConfirmForgetPWEmail = Read-host "Do you want to set it now? [y/n]"
        
        if ($ConfirmForgetPWEmail -ieq "y") {
            $ldapconnection = Get-LDAPConnection
            if ($ForgotPWEnableExist) {
                Set-LDAPUserProperty -UserCN $CN -ldapattrname "mUSRaccountForgotPasswordEnabled" -ldapattrvalue "TRUE" -ldapconnection $ldapconnection
            } else {
                Add-LDAPUserProperty -UserCN $CN -ldapattrname "mUSRaccountForgotPasswordEnabled" -ldapattrvalue "TRUE" -ldapconnection $ldapconnection
            }
            if ($ForgotEmailExist) {
                Set-LDAPUserProperty -UserCN $CN -ldapattrname "mUSRaccountForgotPasswordEmail" -ldapattrvalue "$Email" -ldapconnection $ldapconnection
            } else {
                Add-LDAPUserProperty -UserCN $CN -ldapattrname "mUSRaccountForgotPasswordEmail" -ldapattrvalue "$Email" -ldapconnection $ldapconnection
            }
        } else {
            Write-Host "Job cancelled"
        }
    }
}


function Get-LdapADManager {
    param($Identity)
    $uid = "(uid=$Identity)"
    $ldapentry = Get-LDAPConnectionEntry
    $query = New-Object System.DirectoryServices.DirectorySearcher($ldapentry,$uid)
    $CN = Convert-UIDToCN -uid $Identity -ldapconnection $ldapentry

    $ADManager =        $query.FindOne().properties['manager']
    $SAPManager =       $query.FindOne().properties['musraapmmanager']

    Write-Host -NoNewline "Your AD Manager is`t`t`t: "
    if ($ADManager -ne $null) {
        $ADManager = $ADManager -replace '^CN=|,.*$'
        $ADManager = Convert-CNToUID -cn $ADManager -ldapconnection $ldapentry
        $ADManagerFullName = Get-ADUser $ADManager -Properties displayname | Select-Object -ExpandProperty displayname
        $ADManagerEmail = Get-ADUser $ADManager -Properties userprincipalname | Select-Object -ExpandProperty userprincipalname
        Write-Host "$ADManagerFullName($ADManager) - $ADManagerEmail"
    } else {
        Write-Host "No ADManager is set" -ForegroundColor Red
    }

    # Search SAP Manager
    Write-Host -NoNewline "Your SAP Manager is`t`t`t: "
    if ($SAPManager -ne $null) {
        $SAPManager = $SAPManager -replace '^CN=|,.*$' 
        $SAPManager = Convert-CNToUID -cn $SAPManager -ldapconnection $ldapentry
        $SAPManagerFullName = Get-ADUser $SAPManager -Properties displayname | Select-Object -ExpandProperty displayname
        $SAPManagerEmail = Get-ADUser $SAPManager -Properties userprincipalname | Select-Object -ExpandProperty userprincipalname
        Write-Host "$SAPManagerFullName($SAPManager) - $SAPManagerEmail"
    } else {
        Write-Host "No SAP Manager is set" -ForegroundColor Red
    }

    return $ADManager
}


function Get-LDAPUserDetail {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [String]$Identity,
        [bool]$IsManager
    )
    PROCESS {
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
        $OrgUnit =          $query.FindAll().properties['dirxml-sapp-a-o']
        $ForgotPWEnable =   $query.FindOne().properties['mUSRaccountForgotPasswordEnabled']
        $ForgotEmail =      $query.FindOne().properties['mUSRaccountForgotPasswordEmail']
        $ADManager =        $query.FindOne().properties['manager']
        $SAPManager =       $query.FindOne().properties['musraapmmanager']
        $OrgLevel1 =       $query.FindAll().properties['mUSRorgLevel1']
        $OrgLevel2 =       $query.FindAll().properties['mUSRorgLevel2']
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
        Write-Host "====================================================================================="
        Write-Host "Your Displyname is`t`t`t: $DisplayName"
        Write-Host "====================================================================================="
        Write-Host "Your SAP ID is`t`t`t`t: $SAPID"
        Write-Host -NoNewline "Your OrgUnit is`t`t`t`t: "
        Write-Host "$OrgUnit" # -BackgroundColor Red
        Write-Host "Your Org Level 1 is `t`t: $OrgLevel1"
        Write-Host "Your Org Level 2 is `t`t: $OrgLevel2"
        Write-Host "Your Org Level 3 is `t`t: $OrgLevel3"
        Write-Host "Your Org Level 4 is `t`t: $OrgLevel4"
        Write-Host "Your Email is`t`t`t`t: $Email $EmailExist"
        Write-Host "Your SAP Email is `t`t`t: $SapEmail $SapEmailExist"

        if (!$IsManager) {
            # Normail user
            Set-ForgotPasswordEmail -Identity $Identity
            Get-LdapADManager -Identity $Identity
            $Properties = @{
                DisplayName     = "$DisplayName"
                FullName        = "$FullName"
                SapID           = "$SAPID"
                WorkForceID     = "$WorkForceID"
                SystemWorkForceID = "$SysWorkForceID"
                SapWorkForceID  = "$SAPWorkForceID"
                Email           = "$Email"
                SapEmail        = "$SapEmail"
                SystemEmailAll  = "$SystemEmailAll"
                PmMail          = "$PMMail"
                ADAlias         = "$ADAlias"
                OrgUnit         = "$OrgUnit"
                OrgLevel1       = "$OrgLevel1"
                OrgLevel2       = "$OrgLevel2"
                OrgLevel3       = "$OrgLevel3"
                OrgLevel4       = "$OrgLevel4"  
                ForgotPWEnable  = "$ForgotPWEnable"
                ForgotEmail     = "$ForgotEmail"
                ADManager       = "$ADManager"
                SapManager      = "$SAPManager"
                PrimarySmtpAddress = "$PrimarySmtpAddress"
            }
        } else {
            # Manager
            $Properties = @{
                DisplayName     = "$DisplayName"
                FullName        = "$FullName"
                SapID =     "$SAPID"
                OrgUnit =   "$OrgUnit"
                OrgLevel1 = "$OrgLevel1"
                OrgLevel2 = "$OrgLevel2"
                OrgLevel3 = "$OrgLevel3"
                OrgLevel4 = "$OrgLevel4"
                Email =     "$Email"
                SapEmail =  "$SapEmail"
            }
        }

        Write-Host "====================================================================================="

        # New-Object -TypeName psobject -Property $Properties | Format-List -Property SapId, OrgUnit, OrgLevel1, OrgLevel2, OrgLevel3, OrgLevel4, Email, SapEmail
        
        # return New-Object -TypeName psobject -Property $Properties

    } # PROCESS
} # function


Clear-Host
$Handsome = (Get-ADUser $env:USERNAME).GivenName
Write-Host "====================================================================================="
Write-Host "                        Account Creation PowerScript                                 " -BackgroundColor Blue
Write-Host "                            Hello, $Handsome"
Write-Host "====================================================================================="

if (!$UID) {
    $userid = Read-Host "Please provide the new user ID"
    $UID = Test-ADUser $userid
}

Get-LDAPUserDetail -Identity $UID -IsManager $false
$yourDisplayName = Get-ADUser -Identity $UID -Properties DisplayName | Select-Object -ExpandProperty DisplayName

if ($yourADManager -ne $null) {
    $ConfirmManager = Read-Host "Is the manager correct? (y/n)"
    $yourADManagerDisplayName = $yourADManagerFullName
} else {

    $ConfirmManager ='n'
}

$managerid = Read-host "`nPlease provide the manger name or ID"
if ($ConfirmManager -ine 'y') {
    $yourADManager = Select-User $managerid
    # Write-Host "Searching... Please wait" -ForegroundColor DarkGreen
    $yourADManagerDisplayName = Get-ADUser $yourADManager -Properties displayname | Select-Object -ExpandProperty displayname
}

Get-LDAPUserDetail -Identity $yourADManager -IsManager $true


# Write-Host "+================================================+"
Write-Host "Reference User   : $yourADManagerDisplayName"
write-Host "Target User      : $yourDisplayName"
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
