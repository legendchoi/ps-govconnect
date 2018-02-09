# version 0.1 
. "$PSScriptRoot\Includes\Functions.ps1"

# Local variables
$RootPath = "\\dc1wfs01\home\"
$CTX_Groups = @("CTX CAG VPN") # for external users

# Local functions
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
            # $Registered = $true
        } catch {
            Write-Host "$Group NOT added" -ForegroundColor Red
            Write-Warning $_
            # $Registered = $false
        }
    }
    return $Registered
}

function Remove-Groups {
    param($Identity, $Groups)
    
    foreach ($Group in $Groups) {
        try {
            Remove-ADGroupMember -Identity $Group -Members $Identity -ErrorAction Stop -Confirm:$false
            Write-Host -NoNewline "$Group"
            Write-Host " .....removed" -ForegroundColor Green
            # $Registered = $true
        } catch {
            Write-Host "$Group NOT removed" -ForegroundColor Red
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
            Write-Host "Home folder creation failed: Directory $Path already exist or the user already setup HomeDirectory $TSHomeDirectory" -ForegroundColor Red
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
            $userInfo.psbase.invokeset("TerminalServicesHomeDirectory","\\dc1wfs01\home\$Identity")
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

function Get-CTXGroup {
    param($Identity)
    $ctxug = (Get-ADPrincipalGroupMembership -Identity $Identity).Name -imatch "CTX Users"
    Write-Host "Citrix User Group: " -Nonewline
    Write-Host $ctxug -ForegroundColor Yellow
    return $ctxug
}

function Get-CTXGroups { # from existing use

    param($Identity)
    $ctxug = Get-ADuser -Identity $Identity -Properties memberof | select -ExpandProperty memberof | ? { $_ -like "CN=CTX*"} | % {([regex]::split($_,'^CN=|,.+$'))[1]}
    return $ctxug
}

function Get-Summary {
    param($Identity, $Group)

    $UserName = Get-ADUser $Identity -Properties DisplayName | Select-Object -ExpandProperty DisplayName
    $GroupList = $Group -join ", "

    Write-Host "Summary" -ForegroundColor Magenta
    Write-Host "================================================"
    Write-Host " Citrix Target User: " -NoNewline
    Write-Host "$UserName ($Identity)" -ForegroundColor Green
    Write-Host -NoNewLine " Citrix Target Groups: "
    Write-Host $GroupList -ForegroundColor Green
    Write-Host "================================================"
    Read-Host "Press any keys to continue..."
}

# Main Logic
Clear-Host

# Add/Remove
$Operation = Read-Host "Add(a)/Remove(r) Access?"
# $TicketNumber = Read-Host "What's the ticket number?"

# Select the user
Write-Host "What's the target user?" -ForegroundColor Magenta
$TargetID = Select-User

if ($Operation -ieq 'r') {
    $CTX_Groups = Get-CTXGroups -Identity $TargetID
    Remove-Groups -Identity $TargetID -Groups $CTX_Groups
    write-Note -Identity $TargetID -Option 3 -Comment $CTX_Groups -ConfirmNote 'y'    
} else {
    $Path = ($RootPath + $TargetID).Trim()

    # Select the CTX User Group
    Write-Host "What's the reference user?" -ForegroundColor Magenta
    $ReferenceID = Select-User 
    $CTX_Groups += Get-CTXGroup -Identity $ReferenceID

    # Summary
    Get-Summary -Identity $TargetID -Group $CTX_Groups

    # Create the Citrix Home Directory with N: drive
    Write-Host "Creating HomeDirectory" -ForegroundColor Magenta
    New-TerminalServicesHomeDirectory -Identity $TargetID -Path $Path

    # Assign CTX group membership
    Write-Host "Assigning CTX Groups" -ForegroundColor Magenta
    Add-Groups -Identity $TargetID -Groups $CTX_Groups
} 