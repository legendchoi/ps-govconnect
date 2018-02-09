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
        return $UserFullName
	} catch {
		return $null
	}
}

function Get-DepartmentName {
    [CmdletBinding()]
    param ($HomeDirectoryPath, $EmailDomain)
    $DepartmentName = "Unknown"

    foreach ($DeptName in $DeptTable.Keys) {
        if($DeptTable[$DeptName].HomeDir -eq $HomeDirectoryPath -and $DeptTable[$DeptName].Domain -eq $EmailDomain) { $DepartmentName = $DeptName }
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

function Write-Note {
    [CmdletBinding()]
    param ($Identity, $Memo, $TicketNumber)
    
    # $Memo = "Account Provision Request"
    $Today = Get-Date -Format "dd-MMM-yyyy"
    $Note = "$Memo`: $TicketNumber / $Today"
    $Info = Get-ADUser $Identity -Properties info | %{ $_.info} # % = Foreach-Object
    try {
        Set-ADUser $Identity -Replace @{info="$($Info)`r`n$Note"} -ErrorAction Stop
        Write-Host $Note
        return $true
    } catch {
        return $false
    }
}


$Handsome = (Get-ADUser $env:USERNAME).GivenName


do {

    do {
        Clear-Host
        Write-Host "Hello, $Handsome!`r`n"
        # Reference User ID
        do {
            $SrcAccount = Read-Host 'Reference user ID (Manager)'
            $SrcAccountName = Get-ADUserName -ADUser $SrcAccount
            if ($SrcAccountName) {
                Write-Host -NoNewline "User Name: "
                Write-Host "$SrcAccountName" -ForegroundColor Green
            } else {
                Write-Host "No such a user found. Please try again, dude!" -ForegroundColor Red
            }
        } while ($SrcAccountName -eq $null)

        # Target User ID
        do {
            $DstAccount = Read-Host 'Target user ID'
            $DstAccountName = Get-ADUserName -ADUser $DstAccount
            if ($DstAccountName) {
                Write-Host -NoNewline "User Name: "
                Write-Host "$DstAccountName" -ForegroundColor Green
            } else {
                Write-Host "No such a user found. Please try again, dude!" -ForegroundColor Red

            }
        } while ($DstAccountName -eq $null)

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
    $PathSrc = Get-HomeDirectory -UserID $SrcAccount
    $RootPath = $PathSrc -replace "$SrcAccount", ""
    if ($PathSrc -eq $false) {
        Write-Host "No HomeDirectory has been setup!" -ForegroundColor Red
        $AnyError = $true
    } else {
        Write-Host $PathSrc -ForegroundColor Green
    }

    Write-Host -NoNewline "`tChecking Reference user email address`t`t`t`t: "
    <#
    try {
        Get-Mailbox -Identity $SrcAccount -ErrorAction Stop | Select-Object Name,DisplayName,PrimarySmtpAddress | Out-Null
        $SrcAccountEmailAddress=((Get-mailbox $SrcAccount).Primarysmtpaddress).toString()
        Write-Host "$SrcAccountEmailAddress" -ForegroundColor Green
    } catch {
        Write-Host "$SrcAccountName($SrcAccunt) has no email setup" -ForegroundColor Red
        $AnyError = $true
    }
    #>

    try {
        $SrcAccountEmailAddress = Get-ADUser $SrcAccount | Select-Object -ExpandProperty UserPrincipalName -ErrorAction Stop
        Write-Host "$SrcAccountEmailAddress" -ForegroundColor Green
    } catch {
        Write-Host "$SrcAccountName($SrcAccunt) has no email setup" -ForegroundColor Red
        $AnyError = $true
    }
    
    Write-Host -NoNewline "`tChecking Reference user email domain`t`t`t`t: "
    $EmailDomain = (Get-ADUser $SrcAccount -Properties emailaddress).emailaddress.toString().Split("@")[1]
    Write-Host "$EmailDomain" -ForegroundColor Green

    Write-Host -NoNewline "`tChecking Reference user deprtment name`t`t`t`t: "
    # To determine the department of a DstAccount, two values from the SrcAccount are required 
    # 1.HomeDirectory & 2.Email domain address
    $DepartmentName = Get-DepartmentName -HomeDirectoryPath $RootPath -EmailDomain $EmailDomain
    # For Unisys & Infosys users, additionally required to check group membership to identify
    # as both users use the same Home Directory path & 'servicefirst.nsw.gov.au' email domain name
    if ($DepartmentName -ieq 'Unknown') {
        Write-Host $DepartmentName -ForegroundColor Red
        $AnyError = $true
    } elseif ($DepartmentName -ieq 'Unisys' -or $DepartmentName -ieq 'Infosys') {
        switch -Regex (Get-ADPrincipalGroupMembership $SrcAccount | Select-Object Name) {
            "Unisys Users" {$DepartmentName = "Unisys"}
            "Infosys Users" {$DepartmentName = "Infosys"}
            Default {}
        }
        Write-Host "$DepartmentName" -ForegroundColor Green
    } else {
        Write-Host "$DepartmentName" -ForegroundColor Green
    }


    # Only for PSC user should follow the manager's DL PSC *. If no DL PSC - fall back to general DL PSC All
    <#
    Write-Host "Checking DL PSC..." -ForegroundColor DarkCyan
    if ((Get-ADPrincipalGroupMembership $SrcAccount | Select-Object Name) -match "DL PSC") {
        $Group = Get-ADUser -Identity $SrcAccount -Properties memberof | Select-Object -ExpandProperty memberof
        foreach ($Member in $Group) {
            if ($Member -match "DL PSC") {
                $Member = $Member.toString()
                Write-Host $Member.split('^,OU=')[1]
                # $Table[40] += $Member.split('^,OU=')[1] #Table[41] is PSC Array in $Table. Append any additional DL PSC* to the current PSC Array $Table[39]
                $DeptTable.PSC.ADGroups += $Member.split('^,OU=')[1]
            }
        }
        # Testing to review the $Table[40] = PSC
        Write-Host $Table[40]
        Write-Host $DeptTable.PSC.ADGroups
    } else {
        Write-Host "No DL PSC Found."
    }
    #>

    Write-Host -NoNewline "`tChecking Servicefirst.nsw.gov.au filtering`t`t`t: "
    $Domain = $SrcAccountEmailAddress.Split("@")[1] # same as $EmailDomain
    if ($Domain -ieq "servicefirst.nsw.gov.au") {
        Write-Host "Domain name changed to @govconnect.nsw.gov.au" -ForegroundColor Green
        $Domain = "govconnect.nsw.gov.au"
    } else {
        Write-Host "N/A" -ForegroundColor Green
        # Write-Host "Email Domain name is $Domain"
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
    try {
        Get-Mailbox -Identity $DstAccount -ErrorAction Stop | Select-Object Name,DisplayName,PrimarySmtpAddress | Out-Null
        $DstAccountEmailAddress=((Get-mailbox $DstAccount).Primarysmtpaddress).toString()
        Write-Host "The user already has an emailbox - ""$DstAccountEmailAddress""" -ForegroundColor Red
        $AnyError = $true
        $EmailAlreadyExisted = $true
    } catch {
        # Write-Warning $_
        Write-Host "$DstAccountName($DstAccount) has no email setup" -ForegroundColor Green
    }



    Write-Host -NoNewline "`tChecking Target user new email address availability`t: "
    if ($EmailAlreadyExisted) {
        Write-Host "The email address is not available - ""$DstAccountEmailAddress""" -ForegroundColor Red
        $AnyError = $true
    } else {
        # New email address convention - First.Lastname@domain
        $DstAccountSurName = Get-ADUser -Identity $DstAccount -Properties SurName | select-object -expandproperty SurName
        $DstAccountGivenName = Get-ADUser -Identity $DstAccount -Properties GivenName | select-object -expandproperty GivenName
        if ($DstAccountGivenName -match " ") {
            $DstAccountGivenName = $DstAccountGivenName.split(" ")[0]
        }
        $DstEmailAddress = "$DstAccountGivenName.$DstAccountSurName@$Domain"
        try {
            Get-Mailbox -Identity $DstEmailAddress -ErrorAction Stop | Select-Object Name,DisplayName,PrimarySmtpAddress | Out-Null
            $Aavailable = $false
        } catch {
            $Aavailable = $true
        }

        # Adding number subfix if the initial email address is not available
        if (!$Aavailable) {
            $i = 1
            do {
                $DstEmailAddress = "$DstAccountGivenName.$DstAccountSurName$i@$Domain"
                try {
                    Get-Mailbox -Identity $DstEmailAddress -ErrorAction Stop | Select-Object Name,DisplayName,PrimarySmtpAddress | Out-Null
                    $Aavailable = $false
                    $i++
                } catch {
                    $Aavailable = $true
                }
            } while (!$Aavailable)
        }
        Write-Host "$DstEmailAddress" -ForegroundColor Green
    }

    # Testing... 
    # $AnyError = $false

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



    if ($StartAgain -ieq "s"){$repeat = "y"}
    if ($ConfirmSecond -ieq "c") {$AnyError = $true}


    if (!$AnyError) {

        Write-Host "`r`nSTEP 2: BASIC ACCESS" -ForegroundColor Yellow
        Write-Host -NoNewLine "`tDeprtment Name: "
        Write-Host "$DepartmentName" -ForegroundColor Green
        Write-Host "`tAD Groups: "
        $DeptTable[$DepartmentName].ADGroups | ForEach-Object {
            try {
                Add-ADGroupMember -Identity $_ -Members $DstAccount -ErrorAction Stop
                Write-Host "`t`t$_" -ForegroundColor Green
            } catch {
                Write-Host "`t`t$_" -ForegroundColor Red
                $WithError = $true
            }
        }
        if ($WithError) {
            Write-Host "Done with error" -ForegroundColor DarkRed
        } else {
            Write-Host "Done!" -ForegroundColor Green
        }



        Write-Host "`r`nSTEP 3: Home Directory Configuration" -ForegroundColor Yellow

        # Creating Home Directory
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

        if ($CreatedHomeDirectory) {
            # Assigning a full permission to the user and Drive Letter
            $FileSystemAccessRights = [System.Security.AccessControl.FileSystemRights]"FullControl" 
            $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::"ContainerInherit", "ObjectInherit" 
            $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None 
            $AccessControl =[System.Security.AccessControl.AccessControlType]::Allow
            $NewAccessrule = New-Object System.Security.AccessControl.FileSystemAccessRule ($DstAccount, $FileSystemAccessRights, $InheritanceFlags, $PropagationFlags, $AccessControl)  

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
                Write-Host "There is an error to assign a full permission for $DstAccountName to $Path" -ForegroundColor Red
            }
        }


        Write-Host "`nSTEP 4: Email Creation" -ForegroundColor Yellow
        # Emailbox creation in Exchange server
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

        <#
        STEP 5: A Letter & Note (Optional)
        Create a completion letter and add a note? (y/n)
        Notepad: Letter.txt
        Note: 
        Done!
        #>

        Write-Host "`nSTEP 5: A Letter & Note (Optional)" -ForegroundColor Yellow

        $ConfirmNote = Read-Host "`tWriting a note on $DstAccountName?(y/n)"

        if ($confirmNote -ieq "y") {
            do {
                $TicketNumber = Read-Host "`tTicketNumber please"
                if ($TicketNumber) {
                    if (Write-Note -Identity $DstAccount -Memo "Account Provision Request" -TicketNumber $TicketNumber) {
                        Write-Host "Note Added" -ForegroundColor Green
                    } else {
                        Write-Host "Note error" -ForegroundColor Red
                    }       
                } else {
                    Write-Host "Ticket number is null or invalid. Please provide ticket number" -ForegroundColor Red
                }
            } While (!$TicketNumber)
        }


        # Letter Function part
        $ConfirmLetter = Read-Host "`tPrinting a letter(y/n)"
        if ($ConfirmLetter -ieq 'y') {
            $ADPassword = Read-Host "`tTarget User Password please"
            $SAPID = Get-LdapEntryProperty -Identity $DstAccount -Property "DirXML-sapPID"
            $Letter = Get-LetterNewUser -Identity $DstAccount -Password $ADPassword -SAPID $SapID -Email $DstEmailAddress
            $Letter | Out-File Letter.txt
            Notepad Letter.txt
        }
        Write-Host "`nEND OF PROCESS" -ForegroundColor Yellow
    }

    if($StartAgain -ne 's') {$Repeat = Read-Host "Repeat the batch?(y/n)"}

} while ($Repeat -ieq 'y')

Get-PSSession | Remove-PSSession
Write-Host "Bye"