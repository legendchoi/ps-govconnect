# version 1.2
. "$PSScriptRoot\BlackBox.ps1"

#-Exchange Functions-----------------------------------------------------------------------------
function Get-ConnectExch {
    [CmdletBinding()]
	param ([Parameter()][string]$ConnectionUri = "http://dc1wexcamb01.govnet.nsw.gov.au/PowerShell/")
    if (!(Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" })) {
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri
        Import-Module (Import-PSSession $session -AllowClobber) -Global
    }
}

#-LDAP Connection: Entry-------------------------------------------------------------------------
function Get-LDAPConnectionEntry {
    param (
        $IP = "10.82.15.100:389",
        $BaseDN = "ou=active,o=vault",
        $UserCN = $myCN,
        $UserPW = $myPW,
        $AuthType = "FastBind"
    )
    $UserDN = "cn=$UserCN,ou=active,o=vault"
    return $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$IP/$basedn",$UserDN,$UserPW,$AuthType)
}

function Get-LdapEntryProperty {
    param($Identity, $Property)
    # $Property = "DirXML-sapPID"
    $uidfilter = "(uid=$Identity)"
    $ldapentry = Get-LDAPConnectionEntry
    $query = New-Object System.DirectoryServices.DirectorySearcher($ldapentry,$uidfilter)
    return $query.FindOne().properties[$Property]
}

function Test-PropertyExist {
    param ($Uid, $PropertyName, $ldapconnection)
    $uidfilter = "(uid=$Uid)"
    $query = New-Object System.DirectoryServices.DirectorySearcher($ldapentry,$uidfilter)
    $count = $query.FindOne().properties["$PropertyName"].Count
    if ($count -ge 1) {
        return $true
    } else {
        return $false
    }
}

function Convert-CNToUID {
    param ($cn, $ldapconnection)
    $cnfilter = "(cn=$cn)"
    $query = New-Object System.DirectoryServices.DirectorySearcher($ldapconnection,$cnfilter)
    return $query.FindAll().properties["uid"]
}

function Convert-UIDToCN {
    param ($uid,$ldapconnection)
    $uidfilter = "(uid=$uid)"
    $query = New-Object System.DirectoryServices.DirectorySearcher($ldapentry,$uidfilter)
    return $query.FindAll().properties["cn"]
}

# LDAP Connection: Protocols---------------------------------------------------------------------
function Get-LDAPConnection {
    [CmdletBinding()]
    param (
        $IP = "10.82.15.100:389",
        $BaseDN = "ou=active,o=vault",
        $UserCN = $myCN,
        $UserPW = $myPW
    )
    $UserDN = "cn=$UserCN,ou=active,o=vault"
    $c = New-Object System.DirectoryServices.Protocols.LdapConnection $ip -ea Stop
    $c.SessionOptions.SecureSocketLayer = $false;
    $c.SessionOptions.ProtocolVersion = 3
    $c.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
    $credentials = new-object "System.Net.NetworkCredential" -ArgumentList $userdn,$userpw
    $c.Bind($credentials)
    return $c
}

function Add-LDAPUserProperty {
    [CmdletBinding()]
    param (
        $UserCN,  # = cn=TSR6602,ou=active,o=vault"
        $ldapattrname,  # = "mUSRaccountForgotPasswordEnabled",
        $ldapattrvalue, # = "TRUE"
        $ldapconnection
    )
    $TargetUserDN = "cn=$UserCN,ou=active,o=vault"
    $a = New-Object "System.DirectoryServices.Protocols.DirectoryAttributeModification"
    $a.Name = $ldapattrname
    $a.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add
    $a.Add($ldapattrvalue) | Out-Null
    $r = (new-object "System.DirectoryServices.Protocols.ModifyRequest")
    $r.DistinguishedName = "$targetuserdn"
    $r.Modifications.Add($a) | Out-Null
    $re = $ldapconnection.SendRequest($r)
    if ($re.ResultCode -ne [System.directoryServices.Protocols.ResultCode]::Success)
    {
        write-host "Failed!" -ForegroundColor Red
        # write-host ("ResultCode: " + $re.ResultCode)
        # write-host ("Message: " + $re.ErrorMessage)
    } else {
        Write-host "Added: $ldapattrname = $ldapattrvalue" -ForegroundColor Green
    }
}

function Set-LDAPUserProperty {
    param (
        $targetuserdn,  # = cn=TSR6602,ou=active,o=vault"
        $ldapattrname,  # = "mUSRaccountForgotPasswordEnabled",
        $ldapattrvalue, # = "TRUE"
        $ldapconnection
    )

    $a = New-Object "System.DirectoryServices.Protocols.DirectoryAttributeModification"
    $a.Name = $ldapattrname
    $a.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
    $a.Add($ldapattrvalue) | Out-Null

    $r = (new-object "System.DirectoryServices.Protocols.ModifyRequest")
    $r.DistinguishedName = "$targetuserdn"
    $r.Modifications.Add($a) | Out-Null

    $re = $ldapconnection.SendRequest($r)

    if ($re.ResultCode -ne [System.directoryServices.Protocols.ResultCode]::Success)
    {
        write-host "Failed!" -ForegroundColor Red
        # write-host ("ResultCode: " + $re.ResultCode)
        # write-host ("Message: " + $re.ErrorMessage)
    } else {
        Write-host "Modified: $ldapattrname = $ldapattrvalue" -ForegroundColor Green
    }
}

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
        Write-Host "Your User ID is`t`t`t: $Identity"
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
                DisplayName = "$DisplayName"
                FullName  = "$FullName"
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
}

#-AD Functions------------------------------------------------------------------------------------
function Select-User {
    [CmdletBinding()]
    param ($Identity)

    if (!$Identity) { Write-Host "Username is Empty. Please, provide" -ForegroundColor Red }
    do {
        $repeat = $false

        if (!$Identity) {$UserName = Read-Host "User name or ID"}
        else { $UserName = $Identity }
        
        # UserName check
        if($UserName) {
            if ($UserName.Split(" ").Count -gt 1) {
                $First  = $UserName.Split(" ")[0]
                $Second = $UserName.Split(" ")[1]
                $First = "$First*"
                $Second = "$Second*"
                $UserNameList = get-aduser -Filter {((surname -like $First) -and (givenname -like $Second)) -or ((surname -like $Second) -and (givenname -like $First))}
            } else {

                $username = "*$username*"
                $UserNameList = get-aduser -filter {name -like $username}
            }

            if ($usernamelist.length -gt 1) {
                $Number = 1
                Write-Output $UserNameList |
                    ForEach-Object {New-Object psObject -Property @{'Number'=$Number;'Name'= $_.Name;'FirstName'=$_.GivenName;'LastName'=$_.SurName;'Email' = $_.UserPrincipalName};$Number ++} |
                    Format-Table Number, Name, FirstName, LastName, Email -AutoSize | Out-Host
                
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
                            $username = $usernamelist[$choice].name
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
            } elseif ($UserNameList.length -eq 0) {
                Write-Host "No user found" -ForegroundColor Red
                $repeat = $true
                $Identity = $null
            } else {
                $username = $UserNameList.name
            }
        } else {
            # 
            Write-Host "No user Name or ID provided. Please, provide" -ForegroundColor Red
            $repeat = $true
        }
        
    } while ($repeat)

    $userfullname = get-aduser $UserName -Properties displayname | Select-Object -ExpandProperty displayname
    write-Host -NoNewline "User Name: "
    write-host $userfullname -ForegroundColor green
    return $username
}

function Write-Note {
    [CmdletBinding()]
    param($Identity, $Option)

    $UserFullName = Get-ADUser $Identity -Properties Displayname | Select-Object -ExpandProperty Displayname

    $ConfirmNote = Read-Host "Write a note in $UserFullName's Telephone Tab? (y/n)"
    
    if ($ConfirmNote -ieq "y") {
        $TicketNo = Read-Host "Ticket Number Please"
        $today = Get-date -Format "dd-MMM-yyy"

        switch ($Option) {
            1 { $Note = "Account Provision Request: $TicketNo / $today" }   # New Account Creation
            2 { $Note = "Mailbox Access Provided: $TicketNo / $today" }     # Mailbox Access
            3 { $Note = "Modified Access: $TicketNo / $today" }             # Network Priviledge Change
        }
        Write-Host $Note

        $Info = Get-ADUser $Identity -Properties info | ForEach-Object{ $_.info}
        try {
            Set-ADUser $Identity -Replace @{info="$($Info)`r`n$Note"} -ErrorAction Stop
            Write-Host "Note Added" -ForegroundColor Green
        } catch {
            Write-Error $_
            # Write-Host "Note cancelled" -ForegroundColor Red
        }
    } else {
        Write-Host "Note skipped" -ForegroundColor DarkGreen
    }
}