# version 1.3
. "$PSScriptRoot\BlackBox.ps1"

#-Exchange Functions-----------------------------------------------------------------------------
function Get-ConnectExch {
    [CmdletBinding()]
	param ([Parameter()][string]$ConnectionUri = "http://Dc1wexcamb03.govnet.nsw.gov.au/PowerShell/")
    # param ([Parameter()][string]$ConnectionUri = "http://dc1wexcamb01.govnet.nsw.gov.au/PowerShell/")
    
    if (!(Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" })) {
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri
        Import-Module (Import-PSSession $session -AllowClobber) -Global
    }
}

# Get-ConnectExch

Function Connect-Exch {
    [CmdletBinding()]
	# Param ([parameter()][string]$ConnectionUri = "http://dc1wexcamb01.govnet.nsw.gov.au/PowerShell/")
    param ([Parameter()][string]$ConnectionUri = "http://Dc1wexcamb03.govnet.nsw.gov.au/PowerShell/")
    if (!(Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" })) { 
        Write-Host "Connecting Exchange Server... `nPlease wait..." -ForegroundColor DarkGreen
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri
        Import-Module (Import-PSSession $session -AllowClobber) -Global
    } else {
        Write-Host "Existing Exch Session" -ForegroundColor DarkBlue
    }
}

# Get-ConnectExch

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
    param ($Uid, $PropertyName, $ldapconnection) # no reason for $ladpconnection parameter... can be removed
    $ldapentry = Get-LDAPConnectionEntry
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
    $query = New-Object System.DirectoryServices.DirectorySearcher($ldapconnection,$uidfilter)
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

function Get-LDAPUserProperty {

    param()

    
}

function Set-LDAPUserProperty {
    param (
        $Identity,  # = cn=TSR6602,ou=active,o=vault"
        $UserCN,
        $LDAPAttrName,  # = "mUSRaccountForgotPasswordEnabled",
        $LDAPAttrValue, # = "TRUE"
        $LDAPConnection
    )

    # Write-Host "Hello, $Identity"
    
    if ($Identity) {
        $UserCN = Get-LdapEntryProperty -Identity $Identity -Property "cn"
    } else {
        # $UserCN = $Identity
    }
    $TargetUserDN = "cn=$UserCN,ou=active,o=vault"
    # Write-Host "DN is $TargetUserDN"

    $a = New-Object "System.DirectoryServices.Protocols.DirectoryAttributeModification"
    $a.Name = $ldapattrname
    $a.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
    $a.Add($ldapattrvalue) | Out-Null

    $r = (new-object "System.DirectoryServices.Protocols.ModifyRequest")
    $r.DistinguishedName = "$targetuserdn"
    $r.Modifications.Add($a) | Out-Null
    $re = $ldapconnection.SendRequest($r)

    if ($re.ResultCode -ne [System.directoryServices.Protocols.ResultCode]::Success) {
        write-host "Failed!" -ForegroundColor Red
        # write-host ("ResultCode: " + $re.ResultCode)
        # write-host ("Message: " + $re.ErrorMessage)
    } else {
        Write-host "Modified: $ldapattrname = $ldapattrvalue" -ForegroundColor Green
    }
}

function Set-LDAPUserProperty2 {
    param (
        $Identity,  # = cn=TSR6602,ou=active,o=vault"
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
    $a
    $r
    $re = $ldapconnection.SendRequest($r)
    $re



    if ($re.ResultCode -ne [System.directoryServices.Protocols.ResultCode]::Success) {
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

    Write-Host "Your Forgot PW Enable is: $ForgotPWEnable $ForgotPWEnableExist"
    Write-Host "Your Forgot Email is`t: $ForgotEmail $ForgotEmailExist"

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
    # $SAPManager =       $query.FindOne().properties['musraapmmanager']

    # Write-Host -NoNewline "Your AD Manager is`t`t`t: "
    if ($ADManager -ne $null) {
        $ADManager = $ADManager -replace '^CN=|,.*$'
        $ADManager = Convert-CNToUID -cn $ADManager -ldapconnection $ldapentry
        # $ADManagerFullName = Get-ADUser $ADManager -Properties displayname | Select-Object -ExpandProperty displayname
        # $ADManagerEmail = Get-ADUser $ADManager -Properties userprincipalname | Select-Object -ExpandProperty userprincipalname
        # Write-Host "$ADManagerFullName($ADManager) - $ADManagerEmail"
    } else {
        Write-Host "No ADManager is set" -ForegroundColor Red
    }

    # Search SAP Manager
    <#
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
    #>
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

        # LDAP Search
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
        $ADManager =        $query.FindOne().properties['manager'] -replace '^CN=|,.*$'
        $SAPManager =       $query.FindOne().properties['musraapmmanager']
        $OrgLevel1 =       $query.FindAll().properties['mUSRorgLevel1']
        $OrgLevel2 =       $query.FindAll().properties['mUSRorgLevel2']
        $OrgLevel3 =       $query.FindOne().properties['mUSRorgLevel3']
        $OrgLevel4 =       $query.FindOne().properties['mUSRorgLevel4']

        # Additional Info
        if ($ADManager) {
            $ADManager = Convert-CNToUID -cn $ADManager -ldapconnection $ldapentry
            $ADManagerFullName = (Get-ADUser $ADManager -Properties displayname -ea SilentlyContinue).displayname
            $ADManagerEmail =    (Get-ADUser $ADManager -Properties userprincipalname -ea SilentlyContinue).userprincipalname
        }
        # Check if the properties exist
        $ForgotPWEnableExist =  Test-PropertyExist -Uid $Identity -PropertyName "mUSRaccountForgotPasswordEnabled" -ldapconnection $ldapentry
        $ForgotEmailExist =     Test-PropertyExist -Uid $Identity -PropertyName "mUSRaccountForgotPasswordEmail" -ldapconnection $ldapentry
        $EmailExist =           Test-PropertyExist -Uid $Identity -PropertyName "mail" -ldapconnection $ldapentry
        $SapEmailExist =        Test-PropertyExist -Uid $Identity -PropertyName "mUSRAAsapmail" -ldapconnection $ldapentry
        $SystemEmailAllExist =  Test-PropertyExist -Uid $Identity -PropertyName "mUSRsystemMailAll" -ldapconnection $ldapentry
        $PMMailExist =          Test-PropertyExist -Uid $Identity -PropertyName "mUSRAApmmail" -ldapconnection $ldapentry
        $ADAliasExist =         Test-PropertyExist -Uid $Identity -PropertyName "DirXML-ADAliasName" -ldapconnection $ldapentry


        # SAP Related
        # Write-Host "====================================================================================="
        # Write-Host "Your User ID is`t`t`t: $Identity"
        # Write-Host "Your Displyname is`t`t: $DisplayName"
        Write-Host "====================================================================================="
        Write-Host "Your SAP ID is`t`t: $SAPID"
        Write-Host -NoNewline "Your OrgUnit is`t`t: "
        Write-Host "$OrgUnit" # -BackgroundColor Red
        Write-Host "Your Org Level 1 is `t: $OrgLevel1"
        Write-Host "Your Org Level 2 is `t: $OrgLevel2"
        Write-Host "Your Org Level 3 is `t: $OrgLevel3"
        Write-Host "Your Org Level 4 is `t: $OrgLevel4"
        Write-Host "Your Email is`t`t: $Email $EmailExist"
        Write-Host "Your SAP Email is `t: $SapEmail $SapEmailExist"
        Write-Host "Your AD Manager is`t: $ADManagerFullName"
        Write-Host "Your AD Manager ID`t: $ADManager"
        Write-Host "Your AD Manager Email`t: $ADManagerEmail"

        if (!$IsManager) {
            # Normail user
            Set-ForgotPasswordEmail -Identity $Identity

            $Properties = [ordered]@{
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
                ADManagerFullName= "$ADManagerFullName"
                ADManagerEmail  = "$ADManagerEmail"
                PrimarySmtpAddress = "$PrimarySmtpAddress"
            }
        } else {
            # Manager
            $Properties = [ordered]@{
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

        # New-Object -TypeName psobject -Property $Properties | Format-List -Property *
        # New-Object -TypeName psobject -Property $Properties
        # New-Object -TypeName psobject -Property $Properties | Format-List -Property SapId, OrgUnit, OrgLevel1, OrgLevel2, OrgLevel3, OrgLevel4, Email, SapEmail, ForgotPWEnable, ForgotEmail, ADManager
        # New-Object -TypeName psobject -Property $Properties | Format-List -Property SapId, OrgUnit, OrgLevel1, OrgLevel2, OrgLevel3, OrgLevel4, Email, SapEmail

        # return New-Object -TypeName psobject -Property $Properties

    } # PROCESS
}

#-AD Functions------------------------------------------------------------------------------------
function inputbox_user{
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

    $Form = New-Object System.Windows.Forms.Form
    $Form.width = 300
    $Form.height = 200
    $Form.Text = ”User Details”
    # $Font = New-Object System.Drawing.Font("Times New Roman",12)
    # $Form.Font = $Font
    $Form.StartPosition = "CenterScreen"

    $objLabel = New-Object System.Windows.Forms.Label
    $objLabel.Location = New-Object System.Drawing.Size(10,20) 
    $objLabel.Size = New-Object System.Drawing.Size(280,20) 
    $objLabel.Text = "Please enter the User name or ID in the space below:"
    $Form.Controls.Add($objLabel) 

    $objTextBox = New-Object System.Windows.Forms.TextBox 
    $objTextBox.Location = New-Object System.Drawing.Size(10,40) 
    $objTextBox.Size = New-Object System.Drawing.Size(260,20) 
    $Form.Controls.Add($objTextBox)


    # $eventHandler = [System.EventHandler]{$objTextBox.Text;$form.Close()}
    <#
    $eventHandler = [System.EventHandler]{
        $textBox1.Text
        $textBox2.Text
        $textBox3.Text
        $form.Close()
    }
    #>

    $OKButton = new-object System.Windows.Forms.Button
    $OKButton.Location = new-object System.Drawing.Size(15,100)
    $OKButton.Size = new-object System.Drawing.Size(100,40)
    $OKButton.Text = "OK"
    # $OKButton.Add_Click({Validate -Text $objTextBox.Text})
    # $OKButton.Add_Click({$Form.Close()})
    $OKButton.Add_Click({$objTextBox.Text;$Form.Close()})
    $form.Controls.Add($OKButton)

    $CancelButton = new-object System.Windows.Forms.Button
    $CancelButton.Location = new-object System.Drawing.Size(155,100)
    $CancelButton.Size = new-object System.Drawing.Size(100,40)
    $CancelButton.Text = "Cancel"
    $CancelButton.Add_Click({$Form.Close()})
    $form.Controls.Add($CancelButton)
    
    $Form.Add_Shown({$Form.Activate()})
    [void] $Form.ShowDialog()
    
    return $objTextBox.Text
}


function Select-User {
    [CmdletBinding()]
    param ([string]$Identity,[string]$Flag)
    # What is the Flag for??? Why I set this up???

    # if (!$Identity) { Write-Host "Please, provide" -ForegroundColor Red }
    # Write-Host $flag

    do {
            $repeat = $false

            if (!$Identity) {
                $UserName = (Read-Host "User name or ID").Trim()
                # $UserName = inputbox_user
            } else {
                $UserName = $Identity.Trim()
            }
        
            if($UserName) {

                if ($UserName -ine $Flag) {
                    # Do as normal

                    if ($UserName.Split(" ").Count -gt 1) {
                        $First  = $UserName.Split(" ")[0] -replace ",", ""
                        $Second = $UserName.Split(" ")[1]
                        $First = "$First*"
                        $Second = "$Second*"
                        $fs = "$First $Second"
                        $sf = "$Second $First"
                        $UserNameList = get-aduser -Filter {((surname -like $First) -and (givenname -like $Second)) -or ((surname -like $Second) -and (givenname -like $First)) -or ((Displayname -like $FS) -or (Displayname -like $SF))} -Properties * | sort DisplayName
                    } else {
                        $UserName = "$UserName*"
                        $UserNameList = Get-ADUser -Filter {Name -like $UserName -or GivenName -like $UserName -or Surname -like $UserName -or UserPrincipalName -like $UserName -or DisplayName -like $UserName} -Properties * | sort DisplayName
                    }

                    if ($usernamelist.length -gt 1) {
                        $Number = 1
                        $UserNameList |
                            ForEach-Object {New-Object psObject -Property @{'Number'=$Number;'SamAccountName'= $_.SamAccountName;'FirstName'=$_.GivenName;'LastName'=$_.SurName;'DisplayName'=$_.DisplayName;'Email' = $_.UserPrincipalName};$Number ++} | # sort Displayname |
                            Format-Table Number, SamAccountName, FirstName, LastName, DisplayName, Email -AutoSize | Out-Host
                
                        do {
                            $repeatchoice = $false
                            $choice = Read-host "Please select the user or [X] to try again"

                            if ($choice -match "[0-9]") {
                                $choice = [int]$choice
                                if ($choice -gt $usernamelist.length) {
                                    write-host "Input invalid. Too much number detected." -ForegroundColor Red
                                    $repeatchoice = $true
                                } else { 
                                    $choice = $choice -1
                                    $username = $usernamelist[$choice].SamAccountName
                                }
                            } elseif ($choice -ieq 'x') {
                                $repeatchoice = $false
                                $repeat = $true
                                $Identity = $false
                            } else {
                                write-host "Input ivalid. No number detected." -ForegroundColor Red
                                $repeatchoice = $true
                            }
                        } while ($repeatchoice)
                    } elseif ($UserNameList.length -eq 0) {
                        Write-Host "No user found" -ForegroundColor Red
                        $repeat = $true
                        $Identity = $null
                    } else {
                        $username = $UserNameList.SamAccountName
                    }

                } else {
                    # Stop processing it then return $UserName as $Flag
                    $UserName = $Flag
                }






            } else {
                Write-Host "No user Name or ID provided. Please, provide" -ForegroundColor Red
                $repeat = $true
            }
        } while ($repeat)

    if ($UserName -ine $Flag) {
        $userfullname =     (Get-ADUser $UserName -Properties displayname).DisplayName
        $userEmailAddress = (Get-ADUser $UserName -Properties UserPrincipalName).UserPrincipalName
        $userEmpID =        (Get-ADUser $UserName -Properties EmployeeID).EmployeeID
        $userEnabled =      (Get-ADUser $UserName).Enabled

        write-Host "User Name: " -NoNewline
        if ($userEnabled -eq $true) {  
            write-host $userfullname -ForegroundColor Green
        } else {
            write-host "$userfullname (Disabled)"-ForegroundColor Red
        }
        
        
        Write-Host "User ID  : $UserName"
        Write-Host "Email    : $userEmailAddress"
    }

    return $UserName
}

function Write-Note {
    [CmdletBinding()]
    param($Identity, $Option, $Comment, $ConfirmNote, $TicketNumber)

    $UserFullName = (Get-ADUser $Identity -Properties Displayname).Displayname

    if(!$ConfirmNote){$ConfirmNote=Read-Host "Write a note in $UserFullName's Telephone Tab? (y/n)"}
    
    if ($ConfirmNote -ieq "y") {
        if (!$TicketNumber){$TicketNumber=Read-Host "Ticket Number Please"}
        $today = Get-date -Format "dd-MMM-yyy"

        switch ($Option) {
            1 { $Note = "Account Provision Request: $TicketNumber / $today" }   # New Account Creation
            2 { $Note = "Mailbox Access Provided: $TicketNumber / $today" }     # Mailbox Access
            3 { $Note = "Modified Access: $TicketNumber / $today" }             # Network Priviledge Change
            4 { $Note = "Account disabled: $TicketNumber / $today"}
            5 { $Note = "Access Removed: $TicketNumber / $today" }
        }
        Write-Host $Note

        # $Info = Get-ADUser $Identity -Properties info | ForEach-Object{ $_.info}
        $Info = (Get-ADUser $Identity -Properties info).info
        try {
            Set-ADUser $Identity -Replace @{info="$Info`r`n$Note`r`n$Comment"} -ErrorAction Stop
            Write-Host "Note Added" -ForegroundColor Green
        } catch {
            Write-Error $_
            # Write-Host "Note cancelled" -ForegroundColor Red
        }
    } else {
        Write-Host "Note skipped" -ForegroundColor DarkGreen
    }
}

<# 
$DCs = (Get-ADGroupMember "Domain Controllers").name
$Info = (Get-ADUser Choih -Properties info).info
$Note = "Account Test haha"
$Comment = (Get-ADPrincipalGroupMembership choih).name | % {"`r`n$_"}
$DCs | % { Set-ADUser choih -Replace @{info="$Info`r`n$Note`r`n$Comment"} -Server $_ }
#>


#- Account Creation Functions --------------------------------------------------------------------
function Get-ADUserName {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$True)][String]$ADUser)

    $ADUser = $ADUser.Trim()
	try {
		$UserFullName = Get-ADUser -Identity $ADUser -Properties DisplayName -ErrorAction Stop | select-object -expandproperty DisplayName
        Write-Host -NoNewline "User Name: "
        Write-Host $UserFullName -ForegroundColor Green
        return $UserFullName
	} catch {
        Write-Host "No such a user found." -ForegroundColor Red
		return $null
	}
}

function Test-ADUser {
    param ($Identity)
    if (!$Identity) { Write-Host "Username is Empty. Please, provide" -ForegroundColor Red }
    do {
        if (!$Identity) { $Identity = Read-Host 'User ID' }
        try {
            Get-ADUser -Identity $Identity -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "No such a user found. Please try again, dude!" -ForegroundColor Red
            $Identity = $false
        }
    } while (!$Identity)
    return $Identity
}

function Get-DepartmentName {
    [CmdletBinding()]
    param ($HomeDirectoryPath, $EmailDomain)
    # $DepartmentName = "Unknown"
    $DepartmentName= $false

    foreach ($DeptName in $DeptTable.Keys) {
        if($DeptTable[$DeptName].HomeDir -eq $HomeDirectoryPath -and $DeptTable[$DeptName].Domain -eq $EmailDomain) 
        { $DepartmentName = $DeptName }
    }

    if ($DepartmentName -ieq 'Unisys' -or $DepartmentName -ieq 'Infosys') {
        switch -Regex (Get-ADPrincipalGroupMembership $SrcAccount | Select-Object Name) {
            "Unisys Users" {$DepartmentName = "Unisys"}
            "Infosys Users" {$DepartmentName = "Infosys"}
        }
        # Write-Host "$DepartmentName" -ForegroundColor Green
    }
    return $DepartmentName
}

function Get-HomeDirectory {
    [CmdletBinding()]
	param ($UserID)

	try {
		$HomeDirectory = Get-ADUser -Identity $UserID -Properties HomeDirectory -ErrorAction Stop | Select-Object -ExpandProperty HomeDirectory
		return $HomeDirectory
	} catch {
		return $false
	}
}

function Test-HomeDirectory {
    [CmdletBinding()]
    param ($Identity)
    
    try {
        $HomeDirectory = Get-ADUser -Identity $Identity -Properties HomeDirectory -ErrorAction Stop | Select-Object -ExpandProperty HomeDirectory
        Write-Host $HomeDirectory -ForegroundColor Green
        return $HomeDirectory
    } catch {
        Write-Host "No HomeDirectory has been setup!" -ForegroundColor Red
        return $false
    }
}

function Test-EmailFromAD {
    param ($Identity)
    try {
        $EmailAddress = Get-ADUser $Identity | Select-Object -ExpandProperty UserPrincipalName -ErrorAction Stop
        # Write-Host "$EmailAddress" -ForegroundColor Green
        return $EmailAddress
    } catch {
        $UserName = Get-ADUser $Identity | Select-Object -ExpandProperty DisplayName
        # Write-Host "$UserName($Identity) has no email setup" -ForegroundColor Red
        return $false
    }
}

function Test-Email {
    param($Identity)

    try {
        $EmailAddress=((Get-mailbox $Identity -ErrorAction Stop).Primarysmtpaddress).toString()
        return $EmailAddress
    } catch {
        return $false
    }
}

function New-EmailAddress {
    param ($Identity, $Domain)
    # New email address convention - First.Lastname@domain
    $SurName = Get-ADUser -Identity $Identity -Properties SurName | select-object -expandproperty SurName
    $GivenName = Get-ADUser -Identity $Identity -Properties GivenName | select-object -expandproperty GivenName
    
    $GivenName = $GivenName.split(" ")[0]
    $SurName = $SurName.split(" ")[0]

    $EmailAddress = "$GivenName.$SurName@$Domain"
    try {
        Get-Mailbox -Identity $EmailAddress -ErrorAction Stop | Select-Object Name,DisplayName,PrimarySmtpAddress | Out-Null
        $Aavailable = $false
    } catch {
        $Aavailable = $true
    }

    # Adding number subfix if the initial email address is not available
    if (!$Aavailable) {
        $i = 1
        do {
            $EmailAddress = "$GivenName.$SurName$i@$Domain"
            try {
                Get-Mailbox -Identity $EmailAddress -ErrorAction Stop | Select-Object Name,DisplayName,PrimarySmtpAddress | Out-Null
                $Aavailable = $false
                $i++
            } catch {
                $Aavailable = $true
            }
        } while (!$Aavailable)
    }

    return $EmailAddress
}

function Set-DeptGroups {
    param(
        $Identity,
        $DepartmentName,
        $DepartmentTable
    )

    $DepartmentTable[$DepartmentName].ADGroups | ForEach-Object {
        try {
            Add-ADGroupMember -Identity $_ -Members $Identity -ErrorAction Stop
            Write-Host "`t`t$_" -ForegroundColor Green
        } catch {
            Write-Host "`t`t$_" -ForegroundColor Red
            $WithError = $true
        }
    }
    if ($WithError) { 
        Write-Host "Done with error" -ForegroundColor DarkRed
        return $false
    } else {            
        Write-Host "Done!"           -ForegroundColor Green
        return $true
    }
}

function New-HomeDirectory {
    param ($Identity,$Path)
    try {
        New-Item -ItemType Directory -Path $Path -ErrorAction Stop
        Write-Host -NoNewline "`tHome Directory created: "
        Write-Host $Path -ForegroundColor Green
        $CreatedHomeDirectory = $true
    } catch {
        # Write-Error $_
        Write-Host "Home folder creation failed" -Red
        $CreatedHomeDirectory = $false
    }

    # Assigning a permission
    if ($CreatedHomeDirectory) {
        # Assigning a full permission to the user and Drive Letter
        $FileSystemAccessRights = [System.Security.AccessControl.FileSystemRights]"FullControl" 
        $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::"ContainerInherit", "ObjectInherit" 
        $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
        $AccessControl =[System.Security.AccessControl.AccessControlType]::Allow
        $NewAccessrule = New-Object System.Security.AccessControl.FileSystemAccessRule ($Identity, $FileSystemAccessRights, $InheritanceFlags, $PropagationFlags, $AccessControl)  

        $currentACL = Get-ACL -path $Path
        $currentACL.SetAccessRule($NewAccessrule)
        # Set-ACL -path $Path -AclObject $currentACL

        $setACL = $true
        try { Set-ACL -path $Path -AclObject $currentACL -ErrorAction Stop } 
        catch { $setACL = $false }

        $setUser = $true
        try { Set-ADuser $DstAccount -HomeDirectory "$Path" -HomeDrive H: -ErrorAction Stop }
        catch { $setUser = $false }

        if ($setACL -and $setUser) {
            # Get-HomeDirectory -UserID $DstAccount
            Write-Host -NoNewLine "`tHome Directory permission: "
            Write-Host "Granted" -ForegroundColor Green
        } else {
            $UserName = Get-ADUser $Identity | Select-Object -ExpandProperty DisplayName
            Write-Host "There is an error in assigning a full permission for $UserName to $Path" -ForegroundColor Red
        }
    }
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

# Password Reset --------------------------------------------------------------------------------
function Random-Password {
    $alphabet = [char[]]([char]'a'..[char]'z')
    $number = 0..9
    $Symbol = @("!","@")

    $Passwd = ""
    $Passwd += (Get-Random -InputObject $alphabet).ToString().ToUpper()
    $Passwd += Get-Random -InputObject $number
    $Passwd += Get-Random -InputObject $Symbol
    $Passwd += Get-Random -InputObject $alphabet
    $Passwd += ((Get-Random -InputObject $alphabet -Count 5) -join "").ToString()

    return $Passwd 
}

function Reset-Password {
    param($Identity, $NewPassword)
    
    if (!$NewPassword) {
        $NewPassword = (Random-Password).toString()
    }

    $Password = ConvertTo-SecureString -String $NewPassword -AsPlainText -Force

    # I found there is a password sync probem if reset password from one logonserver. So do it all!
    try {
        Set-ADAccountPassword -Server govnetdc01 -Identity $Identity -Reset -NewPassword $Password -ErrorAction Stop
        Set-ADAccountPassword -Server govnetdc02 -Identity $Identity -Reset -NewPassword $Password -ErrorAction Stop
        Set-ADAccountPassword -Server govnetdc03 -Identity $Identity -Reset -NewPassword $Password -ErrorAction Stop
        Set-ADAccountPassword -Server govnetdc04 -Identity $Identity -Reset -NewPassword $Password -ErrorAction Stop
        Set-ADAccountPassword -Server govnetdc05 -Identity $Identity -Reset -NewPassword $Password -ErrorAction Stop
        Set-ADAccountPassword -Server govnetdc07 -Identity $Identity -Reset -NewPassword $Password -ErrorAction Stop

        Write-Host "Password reset: $NewPassword" -ForegroundColor Green
    } catch {
        Write-Host "Password reset failed. The provided password does not meet the password requirement" -ForegroundColor Red
        Write-Host "The password must be alphnumeric and include a special character" -ForegroundColor Red
    } 
    
}

function Get-ADUserLastLogon([string]$userName) {
    $dcs = [system.directoryservices.activedirectory.Forest]::GetCurrentForest().domains | %{$_.DomainControllers.name}
    $array = @()
    foreach($dc in $dcs) {
        $hash = @{}
        $hostname = $dc
        $user = Get-ADUser $userName -Server $hostname -Properties lastLogon
        $lngexpires = $user.lastLogon
        if (-not ($lngexpires)) {$lngexpires = 0 }
        If (($lngexpires -eq 0) -or ($lngexpires -gt [DateTime]::MaxValue.Ticks)) {
            $LastLogon = "<Never>"
        } Else {
            $Date = [DateTime]$lngexpires
            $LastLogon = $Date.AddYears(1600).ToLocalTime()
            
            $hash.hostname = $hostname
            $hash.LastLogon = $LastLogon
            
            $array += $hash
        }
    }
    # $array.ForEach({[PSCustomObject]$_}) | Format-Table -AutoSize
    $table = $array | % { new-object PSObject -Property $_} | sort-object lastlogon
    
    Write-Output ($table | Format-Table -AutoSize | Out-String).Trim()
}

function Get-ADUserAccountStatus {
    param($Identity)
    $Status = Get-ADUser $Identity -Properties * | Select-Object Enabled, LockedOut, SamAccountName, EmployeeID, Office, Company, Department, TelephoneNumber
    Write-Output ($Status | Format-List | Out-String).Trim()
}

function Get-ADUserAccountLockedStatus {
    param($Identity)
    $LockedOut = (Get-ADUser $Identity -Properties LockedOut).LockedOut
    return $LockedOut
}

function Get-ADUserPasswordStatus {
    param($Identity)
    $Status = Get-ADUser $Identity -Properties PasswordLastSet, msDS-UserPasswordExpiryTimeComputed | Select-Object PasswordLastSet, @{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
    Write-Output ($Status | Format-List | Out-String).Trim()
}

function Get-Phonetic {
    Param (
        # List of characters to translate to phonetic alphabet
        [Parameter(Mandatory=$true,ValueFromPipeLine=$true)]
        [Char[]]$Char,
        # Hashtable containing a char as key and phonetic word as value
        [HashTable]$PhoneticTable = @{
            'a' = 'alpha'   ;'b' = 'bravo'   ;'c' = 'charlie';'d' = 'delta';
            'e' = 'echo'    ;'f' = 'foxtrot' ;'g' = 'golf'   ;'h' = 'hotel';
            'i' = 'india'   ;'j' = 'juliett' ;'k' = 'kilo'   ;'l' = 'lima' ;
            'm' = 'mike'    ;'n' = 'november';'o' = 'oscar'  ;'p' = 'papa' ;
            'q' = 'quebec'  ;'r' = 'romeo'   ;'s' = 'sierra' ;'t' = 'tango';
            'u' = 'uniform' ;'v' = 'victor'  ;'w' = 'whiskey';'x' = 'x-ray';
            'y' = 'yankee'  ;'z' = 'zulu'    ;'0' = 'Zero'   ;'1' = 'One'  ;
            '2' = 'Two'     ;'3' = 'Three'   ;'4' = 'Four'   ;'5' = 'Five' ;
            '6' = 'Six'     ;'7' = 'Seven'   ;'8' = 'Eight'  ;'9' = 'Nine';
            '.' = 'Point'   ;'!' = 'Exclamationmark';'?' = 'Questionmark'; '@' = 'At Symbol'
        }
    )
    Process {
        $Result = Foreach($Character in $Char) {
            if($PhoneticTable.ContainsKey("$Character")) {
                if([Char]::IsUpper([Char]$Character)) {
                    [PSCustomObject]@{
                        Char = $Character;Phonetic = $PhoneticTable["$Character"].ToUpper()
                    }
                }
                else {
                    [PSCustomObject]@{
                        Char = $Character;Phonetic = $PhoneticTable["$Character"].ToLower()
                    }
                }
            }
            else {
                [PSCustomObject]@{
                    Char = $Character;Phonetic = $Character
                }
            }
            
        }
        "{0}`n{1}" -f ('Candidate Password: {0}'-f-join$Char), ($Result | Format-Table -AutoSize | Out-String).Trim()
        # "`n{0}`n{1}" -f ($Result | Format-Table -AutoSize | Out-String)
    }
}