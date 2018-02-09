<#
version 1.2
#>
. "$PSScriptRoot\BlackBox.ps1"

function Get-ConnectExch {
    [CmdletBinding()]
	param ([Parameter()][string]$ConnectionUri = "http://dc1wexcamb01.govnet.nsw.gov.au/PowerShell/")
    if (!(Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" })) {
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri
        Import-Module (Import-PSSession $session -AllowClobber) -Global
    }
}

# LDAP Connection: Entry
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

# LDAP Connection: System.DirectoryServices.Protocols.LdapConnection
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

# ADD LDAP
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

# Modify LDAP
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

function Select-User {
    param ($Identity)

    do {
        $repeat = $false
        if (!$Identity) {$UserName = Read-Host "User name or ID"}
        
        # UserName check
        if($UserName) {
            if ($UserName.Split(" ").Count -gt 1) {
                $First  = $UserName.Split(" ")[0]
                $Second = $UserName.Split(" ")[1]
                $First = "*$First*"
                $Second = "*$Second*"
                $UserNameList = get-aduser -Filter {((surname -like $First) -and (givenname -like $Second)) -or ((surname -like $Second) -and (givenname -like $First))}
            } else {

                $username = "*$username*"
                $UserNameList = get-aduser -filter {name -like $username}
            }

            if ($usernamelist.length -gt 1) {
                $Number = 1
                $UserNameList |
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
            } else {
                $username = $UserNameList.name
            }
        } else {
            # 
            Write-Host "No user Name or ID provided. Please, provide" -ForegroundColor Red
            $repeat = $true
        }

        # UserNameList check
        
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
            1 { $Note = "Account Provision Request: $TicketNo / $today" }
            2 { $Note = "Mailbox Access Provided: $TicketNo / $today" }
            3 { $Note = "Modified Access: $TicketNo / $today" }
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
    }
}