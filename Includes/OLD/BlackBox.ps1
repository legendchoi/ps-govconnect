# Blackbox v1.2

try {
    $MyCredentials = IMPORT-CLIXML "$PSScriptRoot\SecureCredential.xml"
    # Write-Host "Yes file" -ForegroundColor Green
} catch {
    # Write-Host "No file" -ForegroundColor Yellow
    $Message = "Please provide your CN

    How to get my CN?
     1. Go to eGuide and provide your ID and click search
     2. Select your `"Meta`" account on left pane and you will see your CN at the top of the page. 
     3. It should look something like
       `"Meta - cn=KFC1234,ou=active,o=vault`""

    $Creds = Get-Credential -Message $Message
    if ($Creds) {
        $Creds | EXPORT-CLIXML "$PSScriptRoot\SecureCredential.xml"
        $MyCredentials = IMPORT-CLIXML "$PSScriptRoot\SecureCredential.xml"
    } else {
        Write-Host "Credential cancelled" -ForegroundColor Red
    }
}
$Encrypted = $MyCredentials.Password | ConvertFrom-SecureString
$SecureString = ConvertTo-SecureString -string $Encrypted
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
$MyPW = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$MyCN = $MyCredentials.UserName