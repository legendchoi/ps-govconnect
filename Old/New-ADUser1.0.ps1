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

<#
function Write-Note {
    [CmdletBinding()]
    param ($Identity, $Memo, $TicketNumber)
    
    # $Memo = "Account Provision Request"
    $Today = Get-Date -Format "dd-MMM-yyyy"
    $Note = "$Memo`: $TicketNumber / $Today"
    $Info = Get-ADUser $Identity -Properties info | ForEach-Object{ $_.info} # % = Foreach-Object
    try {
        Set-ADUser $Identity -Replace @{info="$($Info)`r`n$Note"} -ErrorAction Stop
        Write-Host $Note
        return $true
    } catch {
        return $false
    }
}
#>

function New-ADUser {
    param($ReferenceUser, $TargetUser)

    # $Handsome = (Get-ADUser $env:USERNAME).GivenName

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

        Write-Host "`r`n+----------------------------------------------------+"
        Write-Host -NoNewline "|  Referece User : "
        Write-Host "$SrcAccountName" -ForegroundColor Green
        Write-Host -NoNewline "|  Target User   : "
        Write-Host "$DstAccountName" -ForegroundColor Green
        Write-Host "+----------------------------------------------------+"
        Write-Host "|  The script will run through the steps below.      |"
        Write-Host "+----------------------------------------------------+"
        Write-Host "|  STEP 1: Preliminary Checkup                       |"
        Write-Host "|  STEP 2: Assigning Basic Access                    |"
        Write-Host "|  STEP 3: Home Directory Configuration (H: Drive)   |"
        Write-Host "|  STEP 4: Email creation                            |"
        Write-Host "+----------------------------------------------------+"

        $ConfirmFirst = Read-Host "Press [ENTER] key to continue"
        Write-Host "`rConnecting to Exchange Server. Please wait..."
        Get-ConnectExch

        Write-Host "`nSTEP 1: PRELIMINARY CHECKUP" -ForegroundColor Yellow
        Write-Host -NoNewline "`tChecking Reference user home directory`t`t`t`t: "
        $PathSrc = Test-HomeDirectory -Identity $SrcAccount
        if($PathSrc) { $RootPath = $PathSrc -replace "$SrcAccount", "" } 
        else { $AnyError = $true }

        
        Write-Host -NoNewline "`tChecking Reference user email address`t`t`t`t: "
        $SrcAccountEmailAddress = Test-EmailFromAD -Identity $SrcAccount
        if ($SrcAccountEmailAddress) {
            Write-Host "$SrcAccountEmailAddress" -ForegroundColor Green
        } else {
            Write-Host "$SrcAccountName($SrcAccunt) has no email setup" -ForegroundColor Red
            $AnyError = $true
        }
        
        Write-Host -NoNewline "`tChecking Reference user email domain`t`t`t`t: "
        $Domain = $SrcAccountEmailAddress.Split("@")[1]
        Write-Host "$Domain" -ForegroundColor Green

        Write-Host -NoNewline "`tChecking Reference user deprtment name`t`t`t`t: "
        $DepartmentName = Get-DepartmentName -HomeDirectoryPath $RootPath -EmailDomain $Domain
        if ($DepartmentName) {
            Write-Host "$DepartmentName" -ForegroundColor Green
        } else {
            Write-Host "Unknown" -ForegroundColor Red
            $AnyError = $true
        }

        Write-Host -NoNewline "`tChecking Servicefirst.nsw.gov.au filtering`t`t`t: "
        if ($Domain -ieq "servicefirst.nsw.gov.au") {
            Write-Host "Domain name changed to @govconnect.nsw.gov.au" -ForegroundColor Green
            $Domain = "govconnect.nsw.gov.au"
        } else {
            Write-Host "N/A" -ForegroundColor Green
        }

        Write-Host -NoNewline "`tChecking Target user Home Drive`t`t`t`t`t`t: "
        $PathDst = Get-HomeDirectory -UserId $DstAccount
        if ($PathDst -eq $false) {
            Write-Host "No Home drive has been setup" -ForegroundColor Green
            # $Path = $PathSrc -replace "$SrcAccount", "$DstAccount"
        } else {
            Write-Host "The Home drive already existed - ""$PathDst""" -ForegroundColor Red
            $AnyError = $true
        }

        Write-Host -NoNewline "`tChecking Target user Network Home Folder`t`t`t: "
        $Path = $PathSrc -replace "$SrcAccount", "$DstAccount"
        # Test-Path $Path
        if (Test-Path $Path) {
            Write-Host "The network folder already existed - ""$PathDst""" -ForegroundColor Red
            $AnyError = $true
        } else {
            Write-Host "No folder existed" -ForegroundColor Green
        }

        Write-Host -NoNewline "`tChecking Target user emailbox`t`t`t`t`t`t: "
        $EmailAlreadyExisted = $false
        $DstAccountEmailAddress = Test-Email $DstAccount
        if ($DstAccountEmailAddress) {
            Write-Host "The user already has an emailbox - ""$DstAccountEmailAddress""" -ForegroundColor Red
            $AnyError = $true
            $EmailAlreadyExisted = $true
        } else {
            Write-Host "$DstAccountName($DstAccount) has no email setup" -ForegroundColor Green
        }

        Write-Host -NoNewline "`tChecking Target user new email address availability`t: "
        if ($EmailAlreadyExisted) {
            Write-Host "The email address is not available - ""$DstAccountEmailAddress""" -ForegroundColor Red
            $AnyError = $true
        } else {
            $DstEmailAddress = New-EmailAddress -Identity $DstAccount -Domain $Domain
            Write-Host "$DstEmailAddress" -ForegroundColor Green
        }

        $BasicAccessGroups = $DeptTable[$DepartmentName].ADGroups -join ', '

        if ($AnyError) {
            Write-Host "`r`nThe preliminary checkup has finished with error(s). The script will stop."
            $StartAgain = Read-Host "Press ENTER key to exit or [s] for start again"
        } else {
            Write-Host "`r`nThe preliminary checkup has finished."
            Write-Host "`r`nThe script will setup the user as below."
            Write-Host "+---------------------------------------------------------"
            Write-Host -NoNewline "|  Target User: `t`t`t`t"
            Write-Host "$DstAccountName" -ForegroundColor Green
            Write-Host -NoNewline "|  Target User Department: `t`t"
            Write-Host "$DepartmentName" -ForegroundColor Green
            Write-Host -NoNewline "|  Target User Basic Access: `t"
            Write-Host "$BasicAccessGroups" -ForegroundColor Green
            Write-Host -NoNewline "|  Target User Home Directory: `t"
            Write-Host "$Path" -ForegroundColor Green
            Write-Host -NoNewline "|  Target User Email Address: `t"
            Write-Host "$DstEmailAddress" -ForegroundColor Green
            Write-Host "+---------------------------------------------------------"
            $ConfirmSecond = Read-Host "Press ENTER key to continue or Press [c] to cancel"
        }
        # Flow Control
        if ($StartAgain -ieq "s"){$repeat = "y"}
        if ($ConfirmSecond -ieq "c") {$AnyError = $true}

        if (!$AnyError) {
            Write-Host "`r`nSTEP 2: BASIC ACCESS" -ForegroundColor Yellow
            Write-Host -NoNewLine "`tDeprtment Name: "
            Write-Host "$DepartmentName" -ForegroundColor Green
            Write-Host -NoNewLine "`tAD Groups: "
            Set-DeptGroups -Identity $DstAccount -DepartmentName $DepartmentName -DepartmentTable $DeptTable

            Write-Host "`r`nSTEP 3: Home Directory Configuration" -ForegroundColor Yellow
            New-HomeDirectory -Identity $DstAccount -Path $Path

            Write-Host "`nSTEP 4: Email Creation" -ForegroundColor Yellow
            Enable-Mailbox $DstAccount | Out-Null
            Set-Mailbox $DstAccount -EmailAddresses @{ add=$DstEmailAddress }  -EmailAddressPolicyEnabled $false | Out-Null
            Set-Mailbox $DstAccount -PrimarySmtpAddress $DstEmailAddress | Out-Null
            Write-Host -NoNewline "`tNew Email Address: "
            $PrimarySmtpAddress = Get-Mailbox $DstAccount | Select-Object -ExpandProperty PrimarySmtpAddress
            Write-Host $PrimarySmtpAddress -ForegroundColor Green

            # Modify Email address in Identity Portal
            Write-Host -NoNewline "`tModify Email in IDM (Mail): "
            $ldapentry = Get-LDAPConnectionEntry
            $yourCN = Convert-UIDToCN -uid $DstAccount -ldapconnection $ldapentry
            $ldapconnection = Get-LDAPConnection

            # Set 'mail' property
            if (Test-PropertyExist -Uid $DstAccount -PropertyName "mail" -ldapconnection $ldapentry) {
                Set-LDAPUserProperty -UserCN $yourCN -LdapAttrName "mail" -ldapattrvalue $DstEmailAddress -ldapconnection $ldapconnection
            } else {
                Add-LDAPUserProperty -UserCN $yourCN -ldapattrname "mail" -ldapattrvalue $DstEmailAddress -ldapconnection $ldapconnection
            }

            Write-Host -NoNewline "`tModify Email in IDM (Sapmail): "
            # Set 'mUSRAAsapmail' property 
            if (Test-PropertyExist -Uid $DstAccount -PropertyName "mUSRAAsapmail" -ldapconnection $ldapentry) {
                Set-LDAPUserProperty -UserCN $yourCN -LdapAttrName "mUSRAAsapmail" -ldapattrvalue $DstEmailAddress -ldapconnection $ldapconnection
            } else {
                Add-LDAPUserProperty -UserCN $yourCN -ldapattrname "mUSRAAsapmail" -ldapattrvalue $DstEmailAddress -ldapconnection $ldapconnection
            }

            Write-Host "`nSTEP 5: A Letter & Note (Optional)" -ForegroundColor Yellow
            Write-Note -Identity $DstAccount -Option 1

            # Letter Function
            $ConfirmLetter = Read-Host "`tPrinting a letter(y/n)"
            if ($ConfirmLetter -ieq 'y') {
                $ADPassword = Read-Host "`tTarget User Password please"
                $SAPID = Get-LdapEntryProperty -Identity $DstAccount -Property "DirXML-sapPID"
                $Letter = Get-LetterNewUser -Identity $DstAccount -Password $ADPassword -SAPID $SapID -Email $DstEmailAddress
                $Letter | Out-File Letter.txt
                Notepad Letter.txt
            }

            # End of the process
            Write-Host "`nEND OF PROCESS" -ForegroundColor Yellow
        }

        if($StartAgain -ne 's') {$Repeat = Read-Host "Repeat the batch?(y/n)"}
        if($Repeat -ieq 'y') {
            $ReferenceUser = $null
            $TargetUser = $null
        }

    } while ($Repeat -ieq 'y')

    Get-PSSession | Remove-PSSession
    Write-Host "Bye"
}

# write-Host "Hellow"
# New-ADUser -ReferenceUser saadm -TargetUser choih