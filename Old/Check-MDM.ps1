Clear-Host
$Identity = Read-Host "User Name"
$MobileGroups = @("Mobility Authorised Users", "Mobility Email Exchange")

$memberof = Get-ADUser -Identity $Identity -Properties MemberOf | Select-Object -ExpandProperty MemberOf

$MobilityGroups = $memberof -match "Mobility Authorised Users|Mobility Email Exchange"

if ($MobilityGroups) {
    Write-Host "Yes, MobileIron registered user" -ForegroundColor Green
} else {
    Write-Host "No, MobileIron NOT registered!" -ForegroundColor Red

    $ConfirmRegister = Read-Host "Register MDM? (Y/n)"
    if ($ConfirmRegister -ieq 'y') {
        foreach ($MDMGroup in $MobileGroups) {
            try {
                Add-ADGroupMember -Identity $MDMGroup -Members $Identity -ErrorAction Stop
            } catch {
                i
            }
        }
    } else {
        Write-Host "Cancelled"
    }   
}



<#
Get-ADPrincipalGroupMembership choih | Select-Object -ExpandProperty Name
Get-ADUser -Identity choih -Properties MemberOf | Select-Object -ExpandProperty MemberOf
#>