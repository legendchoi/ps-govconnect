<#
Please change -Identity parmameter as to what you desire to search
#>

# Connecting Exchange
function Get-ConnectExch {
    [CmdletBinding()]
	param ([Parameter()][string]$ConnectionUri = "http://dc1wexcamb01.govnet.nsw.gov.au/PowerShell/")
    if (!(Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" })) {
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri
        Import-Module (Import-PSSession $session -AllowClobber) -Global
    }
}

Get-ConnectExch

# List Full Access
$Full = Get-MailboxPermission -Identity dpc_hr | Where-Object {($_.user -like "GOVNET\*") -and !($_.user -match " ") -and !($_.user -like "*Admin*") -and ($_.user -notlike "*CAMPBELM*") -and ($_.user -notlike "*SINGHC3*") -and ($_.user -notlike "*CHENGK2*") -and ($_.user -notlike "GOVNET\MC")}
$arr_fl = $full.user | % { $_ -replace "govnet\\", ""}

# List all users who have 'Send-As' permission
$SendAsList = Get-Mailbox -Identity dpc_hr | Get-ADPermission | where { ($_.ExtendedRights -like "*Send-As*") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") } | Select-Object User
$arr_sa = $SendAsList.user | % { $_ -replace "govnet\\", ""}

# Lists
Write-Host "===== Full Access ====="
$arr_fl | % { (Get-ADUser $_ -Properties displayname).displayname } | sort -Unique

Write-Host "`n===== Send As Access ====="
$arr_sa | % { (Get-ADUser $_ -Properties displayname).displayname } | sort -Unique