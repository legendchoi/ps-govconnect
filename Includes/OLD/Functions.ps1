<# version 1.1 #>

param(
    $myCN = 'My_CN_here', # Provide your CN here
    $myPW = 'My_PW_here'  # Provide your password here
)

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
    # -Property list
    # DirXML-sapPID

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
        if (!$Identity) {$UserName = Read-Host "Please provide the user name"}
        
        # UserName check
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

        # UserNameList check
        if ($usernamelist.length -gt 1) {
            $Number = 1
            $UserNameList |
                ForEach-Object {New-Object psObject -Property @{'Number'=$Number;'Name'= $_.Name;'FirstName'=$_.GivenName;'LastName'=$_.SurName;'Email' = $_.UserPrincipalName};$Number ++} |
                Format-Table Number, Name, FirstName, LastName, Email -AutoSize | Out-Host
            
            do {
                $repeatchoice = $false
                $choice = Read-host "Please select the user"

                if ($choice -match "[0-9]") {
                    $choice = [int]$choice
                    if ($choice -gt $usernamelist.length) {
                        write-host "too much number detected" -ForegroundColor Red
                        $repeatchoice = $true
                    }
                } else {
                    # Not integer
                    write-host "not number detected" -ForegroundColor Red
                    $repeatchoice = $true
                }
            } while ($repeatchoice)

            $choice = $choice - 1
            $username = $usernamelist[$choice].name
        } elseif ($UserNameList.length -eq 0) {
            Write-Host "No user found" -ForegroundColor Red
            $repeat = $true
        } else {
            $username = $UserNameList.name
        }
    } while ($repeat)

    $userfullname = get-aduser $UserName -Properties displayname | Select-Object -ExpandProperty displayname
    write-Host -NoNewline "User Name: "
    write-host $userfullname -ForegroundColor green
    return $username
}