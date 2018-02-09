
<#
$DN = (Get-ADUser $Identity).distinguishedName
$User = [ADSI]"LDAP://$DN"
# $user | select Name, AllowLogon, TerminalServicesProfilePath, TerminalServicesHomeDirectory, TerminalServicesHomeDrive | fl
$User.psbase.invokeset("TerminalServicesHomeDrive","N:")
$User.psbase.invokeset("TerminalServicesHomeDirectory","\\dc1wfs01\home\CHOIH")
$User.setinfo()


Test-Path $Path


check if already existing N:
check if already existing TSHD
if not Test-Path - double check if actual folder exsit
#>

param([string]$Identity)



function Select-User {
    [CmdletBinding()]
    param ($Identity)

    # if (!$Identity) { Write-Host "Please, provide" -ForegroundColor Red }

    do {
        $repeat = $false

        if (!$Identity) {
            $UserName = (Read-Host "User name or ID").Trim()
            # $UserName = $UserName.Trim()
        } else {
            $UserName = $Identity.Trim()
        }
        
        if($UserName) {
            if ($UserName.Split(" ").Count -gt 1) {
                # Write-Host "### Test: More than 1 ###"
                $First  = $UserName.Split(" ")[0] -replace ",", ""
                $Second = $UserName.Split(" ")[1]
                $First = "$First*"
                $Second = "$Second*"
                $UserNameList = get-aduser -Filter {((surname -like $First) -and (givenname -like $Second)) -or ((surname -like $Second) -and (givenname -like $First))}
            } else {
                # Write-Host "### Test: less than 1 ###"
                $UserName = "$UserName*"
                $UserNameList = Get-ADUser -Filter {Name -like $UserName -or GivenName -like $UserName -or Surname -like $UserName -or UserPrincipalName -like $UserName}
            }

            if ($usernamelist.length -gt 1) {
                $Number = 1
                $UserNameList |
                    ForEach-Object {New-Object psObject -Property @{'Number'=$Number;'SamAccountName'= $_.SamAccountName;'FirstName'=$_.GivenName;'LastName'=$_.SurName;'Email' = $_.UserPrincipalName};$Number ++} |
                    Format-Table Number, SamAccountName, FirstName, LastName, Email -AutoSize | Out-Host
                
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
                            
                            $username = $usernamelist[$choice].SamAccountName
                            # Write-Host "### Test $Uername ###"

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
            } 
            elseif ($UserNameList.length -eq 0) {
                Write-Host "No user found" -ForegroundColor Red
                $repeat = $true
                $Identity = $null
            } 
            else {
                # Write-Host "### Test: list only 1 exactly ###"
                # Write-Host "User Name List: $UserNameList"
                $username = $UserNameList.SamAccountName

            }
        } else {
            Write-Host "No user Name or ID provided. Please, provide" -ForegroundColor Red
            $repeat = $true
        }
        
    } while ($repeat)

    # Write-Host "### Test: Username $UserName ###"
    $userfullname = get-aduser $UserName -Properties displayname | Select-Object -ExpandProperty displayname
    $userEmailAddress = Get-ADUser $UserName -Properties UserPrincipalName | Select-Object -ExpandProperty UserPrincipalName
    write-Host -NoNewline "User Name: "
    write-host $userfullname -ForegroundColor Yellow -NoNewline
    Write-Host "($UserName) - $userEmailAddress"

    return $username
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

function New-TerminalServicesHomeDirectory {
    param ($Identity,$Path)

    $userDN = (Get-ADUser $Identity).distinguishedName
    $userInfo = [ADSI]"LDAP://$userDN"
    $TSHomeDirectory = $userInfo.TerminalServicesHomeDirectory
    $TSHomeDrive = $userInfo.TerminalServicesHomeDrive

    # Creating Terminal Service Home Directory
    if (!($TSHomeDirectory -and $TSHomeDrive -and (Test-Path $Path))) {
        try {
            New-Item -ItemType Directory -Path $Path -ErrorAction Stop
            Write-Host -NoNewline "Terminal Service Home Directory created: "
            Write-Host $Path -ForegroundColor Green
            $CreatedHomeDirectory = $true
        } catch {
            # Write-Error $_
            Write-Host "Home folder creation failed" -Red
            $CreatedHomeDirectory = $false
        }
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

        # Set Access Control List to the Path
        try { 
            Set-ACL -path $Path -AclObject $currentACL -ErrorAction Stop 
            $setACL = $true
        } catch { 
            $setACL = $false 
        }

        # Set HomeDir and Drive
        try {
            $userInfo.psbase.invokeset("TerminalServicesHomeDrive","N:")
            $userInfo.psbase.invokeset("TerminalServicesHomeDirectory","\\dc1wfs01\home\CHOIH")
            $userInfo.setinfo()
            $setUser = $true
        } catch { 
            $setUser = $false 
        }

        if ($setACL -and $setUser) {
            # Get-HomeDirectory -UserID $DstAccount
            Write-Host -NoNewLine "Home Directory permission: "
            Write-Host "Granted" -ForegroundColor Green
        } else {
            $UserName = Get-ADUser $Identity | Select-Object -ExpandProperty DisplayName
            Write-Host "There is an error in assigning a full permission for $UserName to $Path" -ForegroundColor Red
        }
    }
}

function Select-CTXUser {
    param($Identity, $Manager)

    if ($Manager) {


    }


}


# Main Logic
$RootPath = "\\dc1wfs01\home\"
$CTX_Groups = @("CTX CAG VPN") # for external users


# Select the user
$UserID = Select-User $Identity
$Path = ($RootPath + $UserID).Trim()

# Create the Citrix Home Directory with N: drive
New-TerminalServicesHomeDirectory -Identity $UserID -Path $Path

# Assign CTX group membership
Add-Groups -Identity $Identity -Groups $CTX_Groups





$Domain = (Get-ADuser -Identity choih | Select-Object -ExpandProperty UserPrincipalName).split("@")
$Domain[1]

Get-ADGroup -Filter {Name -like "CTX users*" -and } -Properties Description | ft Name, Description -AutoSize