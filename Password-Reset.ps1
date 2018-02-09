# v0.2
# Password Operation

."$PSScriptRoot\includes\Functions.ps1"

# Main
Clear-Host
$User = Select-User $Identity
Write-Host "-----------------------" -ForegroundColor Magenta
Write-Host "| User Account Status |" -ForegroundColor Magenta
Write-Host "-----------------------" -ForegroundColor Magenta
Get-ADUserAccountStatus -Identity $User

Write-Host "-------------------" -ForegroundColor Magenta
Write-Host "| Password Status |" -ForegroundColor Magenta
Write-Host "-------------------" -ForegroundColor Magenta
Get-ADUserPasswordStatus -Identity $User

# Check lastlogon date/time
Write-Host "----------------------" -ForegroundColor Magenta
Write-Host "| Logging in Records |" -ForegroundColor Magenta
Write-Host "----------------------" -ForegroundColor Magenta
Get-ADUserLastLogon $User

Write-Host "----------------------------" -ForegroundColor Magenta
Write-Host "| Account lockedOut Status |" -ForegroundColor Magenta
Write-Host "----------------------------" -ForegroundColor Magenta
$LockedOut = Get-ADUserAccountLockedStatus -Identity $User
if ($LockedOut) {
    Write-Host "The account is lockedout." -ForegroundColor Red
    Unlock-ADAccount -Identity $User
    Write-Host "The account has been unlocked." -ForegroundColor Green
} else {
    Write-Host "The account is not locked." -ForegroundColor Green
}

Write-Host "------------------" -ForegroundColor Magenta
Write-Host "| Password reset |" -ForegroundColor Magenta
Write-Host "------------------" -ForegroundColor Magenta

Write-Host "Do you require password reset?"
Write-HOst -foreground Yellow "NOTE: The password reset will reset AD account only. SAP password won't sync here. `nHowever, once password is reset here, the user will be able to login to Identity Portal `nto change his/her password which then will sync across all."
$ConfirmPasswordReset = Read-Host "(Y/n)"
if ($ConfirmPasswordReset -ieq 'y') {
    $Random = Random-Password
    $Random | Get-Phonetic
    $ConfirmReset = Read-Host "`nConfirm to reset (Y/n)?"
    if ($ConfirmReset -ieq 'y') {
        Reset-Password -Identity $User -NewPassword $Random
    } else {
        Write-Host "Skip"
    }
} else {
    Write-Host "Skip"
}