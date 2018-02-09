# Includes $Table and Hash version of Table $HashTable
. "$PSScriptRoot\includes\DeptTable.ps1"
. "$PSScriptRoot\includes\Letter-Service.ps1"
. "$PSScriptRoot\includes\Functions.ps1"

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
        # $EmailAddress = Get-ADUser $Identity | Select-Object -ExpandProperty UserPrincipalName -ErrorAction Stop
        $EmailAddress = Get-ADUser $Identity -Properties * | Select-Object -ExpandProperty mail -ErrorAction Stop
        # Write-Host "$EmailAddress" -ForegroundColor Green
        return $EmailAddress
    } catch {
        # $UserName = Get-ADUser $Identity | Select-Object -ExpandProperty DisplayName
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
    param($Identity, $DepartmentName, $DepartmentTable)

    $DefaultGroups = @("Mobility Authorised Users", "Mobility Email Exchange", "RES_AIRCARD_USER")
    $DefaultGroups | % { Add-ADGroupMember -Identity $_ -Members $Identity }

    $DepartmentTable[$DepartmentName].ADGroups | ForEach-Object {
        try {
            Add-ADGroupMember -Identity $_ -Members $Identity -ErrorAction Stop
            Write-Host "$_" -ForegroundColor Green
        } catch {
            Write-Host "$_" -ForegroundColor Red
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
        New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
        Write-Host -NoNewline "Home Directory created   : "
        Write-Host $Path -ForegroundColor Green
        $CreatedHomeDirectory = $true
    } catch {
        # Write-Error $_
        Write-Host "Home folder creation failed: the directory already existed" -ForegroundColor Red
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
            Write-Host -NoNewLine "Home Directory permission: "
            Write-Host "Granted" -ForegroundColor Green
        } else {
            $UserName = Get-ADUser $Identity | Select-Object -ExpandProperty DisplayName
            Write-Host "There is an error in assigning a full permission for $UserName to $Path" -ForegroundColor Red
        }
    }
}

# New-ADUser Main Function
function New-ADUser {
    param($ReferenceUser, $TargetUser)

    do {
        do {
            Clear-Host
            Write-Host "IT Clients Account Creation" -ForegroundColor Magenta
            # Write-Host "Hello, $Handsome!`r`n"
            # Reference User ID
            if (!$ReferenceUser) { $UserID = Read-Host "Reference user ID (Manager)" }
            else { $UserID = $ReferenceUser }
            $SrcAccount = Test-ADUser $UserID
            $SrcAccountName = Get-ADUserName -ADUser $SrcAccount
            
            # Target User ID
            if (!$TargetUser) { $UserID = Read-Host 'Target user ID' }
            else { $UserID = $TargetUser }
            $DstAccount = Test-ADUser $UserID
            $DstAccountName = Get-ADUserName -ADUser $DstAccount
            # Check if reference and target user are same
            if ($SrcAccount -eq $DstAccount) {
                Write-Host "The reference user and target user are the same." -ForegroundColor Red
                Read-Host "Press [ENTER] key to try again"
            }
        } while ($SrcAccount -eq $DstAccount)

        Write-Host "========================================================================================="
        Write-Host -NoNewline "|  Referece User : "
        Write-Host "$SrcAccountName ($SrcAccount)" -ForegroundColor Green
        Write-Host -NoNewline "|  Target User   : "
        Write-Host "$DstAccountName ($DstAccount)" -ForegroundColor Green
        Write-Host "========================================================================================="
        Write-Host "|  The script will run through the steps below.                                         |"
        Write-Host "-----------------------------------------------------------------------------------------"
        Write-Host "|  STEP 1: Preliminary Checkup                                                          |"
        Write-Host "|  STEP 2: Assigning Basic Access                                                       |"
        Write-Host "|  STEP 3: Home Directory Configuration (H: Drive)                                      |"
        Write-Host "|  STEP 4: Email creation                                                               |"
        Write-Host "========================================================================================="

        $ConfirmFirst = Read-Host "Press [ENTER] key to continue"
        Write-Host "`rConnecting to Exchange Server. Please wait..."
        Get-ConnectExch

        Write-Host "`nSTEP 1: PRELIMINARY CHECKUP" -ForegroundColor Yellow
        Write-Host "-----------------------------------------------------------------------------------------"

        Write-Host -NoNewline "Reference user home directory`t: "
        $PathSrc = Test-HomeDirectory -Identity $SrcAccount
        if($PathSrc) { $RootPath = $PathSrc -replace "$SrcAccount", "" } 
        else { $ErrorRefHomeDir = $true }

        
        Write-Host -NoNewline "Reference user email address`t: "
        $SrcAccountEmailAddress = Test-EmailFromAD -Identity $SrcAccount
        if ($SrcAccountEmailAddress) {
            Write-Host "$SrcAccountEmailAddress" -ForegroundColor Green
        } else {
            Write-Host "$SrcAccountName($SrcAccunt) has no email setup" -ForegroundColor Red
            $ErrorRefEmail = $true
        }

        Write-Host -NoNewline "Reference user email domain`t: "
        $Domain = $SrcAccountEmailAddress.Split("@")[1]
        Write-Host "$Domain" -ForegroundColor Green

        Write-Host -NoNewline "Reference user deprtment name`t: "
        $DepartmentName = Get-DepartmentName -HomeDirectoryPath $RootPath -EmailDomain $Domain
        if ($DepartmentName) {
            Write-Host "$DepartmentName" -ForegroundColor Green
        } else {
            Write-Host "Unknown" -ForegroundColor Red
            $ErrorDeptName = $true
        }

        Write-Host -NoNewline "@servicefirst domain name`t: "
        if ($Domain -ieq "servicefirst.nsw.gov.au") {
            Write-Host "Domain name changed to @govconnect.nsw.gov.au" -ForegroundColor Green
            $Domain = "govconnect.nsw.gov.au"
        } else {
            Write-Host "N/A" -ForegroundColor Green
        }

        Write-Host -NoNewline "Target user Home Drive`t`t: "
        $PathDst = Get-HomeDirectory -UserId $DstAccount
        if ($PathDst -eq $false) {
            Write-Host "No Home drive has been setup" -ForegroundColor Green
            # $Path = $PathSrc -replace "$SrcAccount", "$DstAccount"
        } else {
            Write-Host "already existed - ""$PathDst""" -ForegroundColor Red
            $ErrorTgtHomeDir = $true
        }

        Write-Host -NoNewline "Target user Home Folder`t`t: "
        $Path = $PathSrc -replace "$SrcAccount", "$DstAccount"
        # Test-Path $Path
        if (Test-Path $Path) {
            Write-Host "already existed - ""$PathDst""" -ForegroundColor Red
            $ErrorTgtNetDir = $true
        } else {
            Write-Host "No network folder existed on the file server" -ForegroundColor Green
        }

        Write-Host -NoNewline "Target user emailbox`t`t: "
        $EmailAlreadyExisted = $false
        $DstAccountEmailAddress = Test-Email $DstAccount
        if ($DstAccountEmailAddress) {
            Write-Host "The user already has an emailbox - ""$DstAccountEmailAddress""" -ForegroundColor Red
            $ErrorTgtEmail = $true
            $EmailAlreadyExisted = $true
        } else {
            Write-Host "$DstAccountName($DstAccount) has no email setup" -ForegroundColor Green
        }

        Write-Host -NoNewline "Target user new email address`t: "
        if ($EmailAlreadyExisted) {
            Write-Host "The email address already occupied - ""$DstAccountEmailAddress""" -ForegroundColor Red
            $ErrorTgtEmailName = $true
        } else {
            $DstEmailAddress = New-EmailAddress -Identity $DstAccount -Domain $Domain
            Write-Host "$DstEmailAddress" -ForegroundColor Green
        }
        Write-Host "-----------------------------------------------------------------------------------------"













        $BasicAccessGroups = $DeptTable[$DepartmentName].ADGroups -join ', '
        $AnyError = $ErrorRefHomeDir -or $ErrorRefEmail -or $ErrorDeptName -or $ErrorTgtHomeDir -or $ErrorTgtNetDir -or $ErrorTgtEmail -or $ErrorTgtEmailName
        if ($AnyError) {
            Write-Warning "The preliminary checkup has finished with error(s). Do you still want to continue?"
            $ConfirmError = Read-Host "Press ENTER key to continue or Press [c] to cancel"
        } else {
            Write-Host "`r`nThe preliminary checkup has finished successfully." -ForegroundColor Green
            $ConfirmError = $null
        }

        





    

        if (!$ConfirmError) {
            Write-Host "========================================================================================="
            Write-Host "    The script will setup the user as below."
            Write-Host "-----------------------------------------------------------------------------------------"
            Write-Host -NoNewline " Target User`t`t`t: "
            Write-Host "$DstAccountName" -ForegroundColor Green
            Write-Host -NoNewline " Target User Department`t`t: "
            if ($DepartmentName) { Write-Host "$DepartmentName" -ForegroundColor Green } 
            else { Write-Host "Unknown" -ForegroundColor Red }
            Write-Host -NoNewline " Target User Basic Access`t: "
            if ($BasicAccessGroups) { Write-Host "$BasicAccessGroups" -ForegroundColor Green } 
            else { Write-Host "N/A" -ForegroundColor Red }
            Write-Host -NoNewline " Target User Home Directory`t: "
            if ($Path -ne $false) { Write-Host "$Path" -ForegroundColor Green } 
            else { Write-Host "$Path" -ForegroundColor Red }
            Write-Host -NoNewline " Target User Email Address`t: "
            if ($DstEmailAddress) { Write-Host "$DstEmailAddress" -ForegroundColor Green }
            else { Write-Host "N/A" -ForegroundColor Red }
            Write-Host "========================================================================================="




            Write-Host "`r`nSTEP 2: BASIC ACCESS" -ForegroundColor Yellow
            Write-Host "-----------------------------------------------------------------------------------------"
            Write-Host -NoNewline "Target User Basic Access: "
            if (!$ErrorDeptName) { Write-Host "$BasicAccessGroups" -ForegroundColor Green } 
            else { Write-Host "N/A" -ForegroundColor Red }
            Write-Host "-----------------------------------------------------------------------------------------"
            $ConfirmSecond = Read-Host "Press ENTER key to continue or Press [c] to cancel"

            if (!$ConfirmSecond) {
                Write-Host -NoNewLine "Deprtment Name: "
                if (!$ErrorDeptName) {
                    Write-Host "$DepartmentName" -ForegroundColor Green
                    Write-Host "AD Groups: "
                    Set-DeptGroups -Identity $DstAccount -DepartmentName $DepartmentName -DepartmentTable $DeptTable
                } else {
                    Write-Host "$DepartmentName" -ForegroundColor Red
                    Write-Host -NoNewLine "AD Groups: "
                    Write-Host "N/A" -ForegroundColor Red
                }
            } else {
                Write-Host "Skipped..." -ForegroundColor DarkGreen
            }





            Write-Host "`r`nSTEP 3: HOME DIRECTORY CONFIGURATION" -ForegroundColor Yellow
            Write-Host "-----------------------------------------------------------------------------------------"
            Write-Host -NoNewline "Target User Home Directory: "
            if ($Path -ne $false) { Write-Host "$Path" -ForegroundColor Green }
            else { Write-Host "$Path" -ForegroundColor Red }
            Write-Host "-----------------------------------------------------------------------------------------"
            $ConfirmSecond = Read-Host "Press ENTER key to continue or Press [c] to cancel"

            if (!$ConfirmSecond) {
                if (!($ErrorTgtHomeDir -and $ErrorTgtNetDir)) {
                    New-HomeDirectory -Identity $DstAccount -Path $Path
                } else {
                    Write-Host "Error: Filed to create a Home Drive" -ForegroundColor Red
                }
            
            } else {
                Write-Host "Skipped..." -ForegroundColor DarkGreen
            }








            Write-Host "`nSTEP 4: Email Creation" -ForegroundColor Yellow
            Write-Host "-----------------------------------------------------------------------------------------"
            Write-Host -NoNewline "Target User Email Address: "
            if ($DstEmailAddress) { Write-Host "$DstEmailAddress" -ForegroundColor Green }
            else { Write-Host "N/A" -ForegroundColor Red }
            Write-Host "-----------------------------------------------------------------------------------------"
            $ConfirmSecond = Read-Host "Press ENTER key to continue or Press [c] to cancel"

            if (!$ConfirmSecond) {

                if (!($ErrorTgtEmail -and $ErrorTgtEmailName)) {
                    Enable-Mailbox $DstAccount | Out-Null
                    Set-Mailbox $DstAccount -EmailAddresses @{ add=$DstEmailAddress }  -EmailAddressPolicyEnabled $false | Out-Null
                    Set-Mailbox $DstAccount -PrimarySmtpAddress $DstEmailAddress | Out-Null
                    Write-Host -NoNewline "New Email Address`t`t: "
                    $PrimarySmtpAddress = Get-Mailbox $DstAccount | Select-Object -ExpandProperty PrimarySmtpAddress
                    Write-Host $PrimarySmtpAddress -ForegroundColor Green

                    # Modify Email address in Identity Portal
                    Write-Host -NoNewline "Modifying Email in IDM (Mail)   : "
                    $ldapentry = Get-LDAPConnectionEntry
                    $yourCN = Convert-UIDToCN -uid $DstAccount -ldapconnection $ldapentry
                    $ldapconnection = Get-LDAPConnection

                    # Set 'mail' property
                    if (Test-PropertyExist -Uid $DstAccount -PropertyName "mail" -ldapconnection $ldapentry) {
                        Set-LDAPUserProperty -UserCN $yourCN -LdapAttrName "mail" -ldapattrvalue $DstEmailAddress -ldapconnection $ldapconnection
                    } else {
                        Add-LDAPUserProperty -UserCN $yourCN -ldapattrname "mail" -ldapattrvalue $DstEmailAddress -ldapconnection $ldapconnection
                    }

                    Write-Host -NoNewline "Modifying Email in IDM (Sapmail): "
                    # Set 'mUSRAAsapmail' property 
                    if (Test-PropertyExist -Uid $DstAccount -PropertyName "mUSRAAsapmail" -ldapconnection $ldapentry) {
                        Set-LDAPUserProperty -UserCN $yourCN -LdapAttrName "mUSRAAsapmail" -ldapattrvalue $DstEmailAddress -ldapconnection $ldapconnection
                    } else {
                        Add-LDAPUserProperty -UserCN $yourCN -ldapattrname "mUSRAAsapmail" -ldapattrvalue $DstEmailAddress -ldapconnection $ldapconnection
                    }
                } else {
                    Write-Host "Error: Filed to create a user Emailbox" -ForegroundColor Red
                }




            } else {
                Write-Host "Skipped..." -ForegroundColor DarkGreen
            }




















            Write-Host "`nSTEP 5: A Letter & Note (Optional)" -ForegroundColor Yellow
            Write-Note -Identity $DstAccount -Option 1

            # Letter Function
            $ConfirmLetter = Read-Host "Printing a letter(y/n)"
            if ($ConfirmLetter -ieq 'y') {
                $ADPassword = Read-Host "Please provide the new user's password or press [ENTER] to generate a new one"

                if (!$ADPassword) {
                    $Random = Random-Password
                    Reset-Password -Identity $DstAccount -NewPassword $Random
                    $ADPassword = $Random
                }

                $SAPID = Get-LdapEntryProperty -Identity $DstAccount -Property "DirXML-sapPID"
                $Letter = Get-LetterNewUser -Identity $DstAccount -Manager $SrcAccount -Password $ADPassword -SAPID $SapID -Email $DstEmailAddress
                $Letter | Out-File Letter.txt
                Notepad Letter.txt
            } else {
                Write-Host "Letter skipped..." -ForegroundColor DarkGreen
            }
            if ($DepartmentName -ieq 'Infosys') {
                Write-Host "Note: Letter to be provided for new Infosys users to" -ForegroundColor DarkGreen
                Write-Host "Bijay.Jena@govconnect.nsw.gov.au" -ForegroundColor DarkGreen
                Write-Host "cc: asif.ali@servicefirst.nsw.gov.au;ranjit.katam@servicefirst.nsw.gov.au;Manoj.Sharma@servicefirst.nsw.gov.au ;Ravi.Phani@govconnect.nsw.gov.au;asiff.muhammed@govconnect.nsw.gov.au" -ForegroundColor DarkGreen
            }
            # End of the process
            Write-Host "`nUser account creation completed" -ForegroundColor Yellow
        }

        $Repeat = Read-Host "Create another user? (Y/n)"
        if($Repeat -ieq 'y') {
            $TargetUser     = $null                
            $ReferenceUser  = $null
        }
    } while ($Repeat -ieq 'y')

    Get-PSSession | Remove-PSSession
    Write-Host "Bye"
}

# New-NonITClinet Main Function
function New-NonITClient {
    param (
        $ReferenceUser,
        $TargetUser,
        $TargetUserSAPID,
        $TargetUserEmail
    )

    $ReferenceUserName = (Get-ADUser $ReferenceUser -Properties DisplayName).DisplayName
    $TargetUserName    = (Get-ADUser $TargetUser -Properties DisplayName).DisplayName
    

    $uid = "(uid=$TargetUser)"
    $ldapentry = Get-LDAPConnectionEntry
    $query = New-Object System.DirectoryServices.DirectorySearcher($ldapentry,$uid)
    # $CN = Convert-UIDToCN -uid $Identity -ldapconnection $ldapentry

    $TargetUserSAPID = $query.FindOne().properties['DirXML-sapPID']
    $TargetUserEmail = $query.FindOne().properties['mail']

    # $CN              = (Get-ADUser $TargetUser -Properties adminDisplayName).adminDisplayName
    # $TargetUserSAPID = (Get-ADUser $TargetUser -Properties EmployeeID).EmployeeID
    # $TargetUserEmail = (Get-ADUser $TargetUser -Properties mail).mail


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
    $ConfirmFirst = Read-Host "Press [ENTER] key to continue or [X] to Exit"
    if ($ConfirmFirst -ine 'x') {
        Write-Host "Please, provide the password to produce a letter"
        $PW = Read-Host "Password"
        $letter = Get-LetterNewUser -Identity $TargetUser -Manager $ReferenceUser -Password $PW -SAPID $TargetUserSAPID -Email $TargetUserEmail
        $letter | Out-File Letter-NonIT.txt
        Notepad Letter-NonIT.txt
        Write-Host "Letter printed" -ForegroundColor Green
        Write-Note -Identity $TargetUser -Option 1
    } else {
        Write-Host "Exit"
    }
}


