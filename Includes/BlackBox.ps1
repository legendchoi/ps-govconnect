# Blackbox v1.3

try {
    $MyCredentials = IMPORT-CLIXML "$PSScriptRoot\SecureCredential.xml"
    # Write-Host "Yes file" -ForegroundColor Green
} catch {
    # Write-Host "No file" -ForegroundColor Yellow
    $Message_OLD = "Please provide your CN in User

    How to get my CN?
    1. Go to eGuide and provide your ID and click search
    2. Select your `"Meta`" account on left pane and you will see your CN at the top of the page. 
    3. It should look something like
      `"Meta - cn=KFC1234,ou=active,o=vault`""
	
	do {
		$Message = "$Authentication Please provide your GovConnect password`r`n`r`nNOTE: Please do not change the username autofilled."
		
		$adminDisplayName = (Get-ADUser $env:USERNAME -Properties adminDisplayName).adminDisplayName
		$Creds = Get-Credential -Message $Message -UserName $adminDisplayName
		# $Creds = $host.ui.PromptForCredential("Need credentials", "$Message", "", "$adminDisplayName")

		$DomainUserName = (Get-ADUser $env:USERNAME).Name
		$DomainPassword = $Creds.GetNetworkCredential().password
		
		$CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
		$domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$DomainUserName,$DomainPassword)
		
		
		if ($domain.name -eq $null)	{
			$Authentication = "Authentication failed - please verify your password.`r`n`r`n"
			$PasswordFailed = $true
			# exit #terminate the script.
		} else {
			write-host "Successfully authenticated with domain $domain.name"
			$PasswordFailed = $false
		}
		
	} while ($PasswordFailed)
	
    # Write-Host $Creds

    if (!$Creds) {
		# This part is not working!
        Write-Host "Credential cancelled" -ForegroundColor Blue
		exit
    } else {
		$Creds | EXPORT-CLIXML "$PSScriptRoot\SecureCredential.xml"
        $MyCredentials = IMPORT-CLIXML "$PSScriptRoot\SecureCredential.xml"
    }
}
$Encrypted = $MyCredentials.Password | ConvertFrom-SecureString
$SecureString = ConvertTo-SecureString -string $Encrypted
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
$MyPW = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$MyCN = $MyCredentials.UserName