. "$PSScriptRoot\includes\Functions.ps1"
[System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null

function Remove-AllGroups {
    param($Identity,$TicketNumber)

    $Groups = Get-ADPrincipalGroupMembership $Identity

    foreach ($Group in $Groups) {
        if($Group.Name -ne "Domain Users") {
            Get-ADGroup $Group | Remove-ADGroupMember -Members $Identity -Confirm:$false
            Write-Host "Removed" $Identity "from" $Group.Name; 
        }
    }
    $Comment = $Groups.name | % {"`r`n$_"}
    Write-Note -Identity $Identity -Option 5 -Comment $Comment -ConfirmNote "y" -TicketNumber $TicketNumber
    Write-Host "Done" -ForegroundColor Green
}

function Hide-FromAddressLists {
    param($Identity)

    # Create Exchange PSSession
    Get-ConnectExch

    $UserName = (Get-ADUser -Identity $Identity -Properties DisplayName).DisplayName
    try {
        Set-Mailbox -Identity $Identity -HiddenFromAddressListsEnabled $true -WarningAction Stop -ErrorAction Stop
        Write-Host "$UserName has been removed from the Address List" -ForegroundColor Green
    } catch {
        Write-Host "Failed to remove $UserName from the Address List" -ForegroundColor Red
    }

    # Close Exchange PSSession
    Get-PSSession | Remove-PSSession
}

function Reset-Password {
    param($Identity)
    $Random = (Random-Password).toString()
    $NewPassword = ConvertTo-SecureString -String $Random -AsPlainText -Force
    # I found there is a password sync probem if reset password from one logonserver. So do it all!
    Set-ADAccountPassword -Server govnetdc01 -Identity $Identity -Reset -NewPassword $NewPassword
    Set-ADAccountPassword -Server govnetdc02 -Identity $Identity -Reset -NewPassword $NewPassword
    Set-ADAccountPassword -Server govnetdc03 -Identity $Identity -Reset -NewPassword $NewPassword
    Set-ADAccountPassword -Server govnetdc04 -Identity $Identity -Reset -NewPassword $NewPassword
    Set-ADAccountPassword -Server govnetdc05 -Identity $Identity -Reset -NewPassword $NewPassword
    Set-ADAccountPassword -Server govnetdc07 -Identity $Identity -Reset -NewPassword $NewPassword
    Write-Host "Password reset: $Random" -ForegroundColor Green
}

function Hide-ForgetPassword {
    param($Identity)
    
    $yourForgotPWEnableExist =  Test-PropertyExist -Uid $Identity -PropertyName "mUSRaccountForgotPasswordEnabled"
    $yourForgotEmailExist =     Test-PropertyExist -Uid $Identity -PropertyName "mUSRaccountForgotPasswordEmail"
    $yourForgotPhoneExist =     Test-PropertyExist -Uid $Identity -PropertyName "mUSRaccountForgotPasswordPhone"
    $yourForgotPWEnable =       Get-LdapEntryProperty -Identity $Identity -Property "mUSRaccountForgotPasswordEnabled"
    $yourForgotEmail =          Get-LdapEntryProperty -Identity $Identity -Property "mUSRaccountForgotPasswordEmail"
    $yourForgotPhone =          Get-LdapEntryProperty -Identity $Identity -Property "mUSRaccountForgotPasswordPhone"
    
    if ( $yourForgotPWEnableExist -eq $true -and $yourForgotEmailExist -eq $true) {
        Write-Host "Forgot Password Email Address has been set: $yourForgotEmail"
        
        $ldapconnection = Get-LDAPConnection
        Set-LDAPUserProperty -Identity $Identity -ldapattrname "mUSRaccountForgotPasswordEnabled" -ldapattrvalue "False" -ldapconnection $ldapconnection
        Set-LDAPUserProperty -Identity $Identity -ldapattrname "mUSRaccountForgotPasswordEmail" -ldapattrvalue "" -ldapconnection $ldapconnection
    } else {
        Write-Host "Hey dude! The user hasn't set Forgetten Password Registration. Nothing to do!"
    }
}


function Disable-UserADAccount {
    param ($Identity,$TicketNumber)

    $DCs = (Get-ADGroupMember "Domain Controllers").name

    if ((Get-ADUser $Identity -Properties EmployeeID).EmployeeID) {
        Write-Host "Account cannot be disabled - SAP account associated" -ForegroundColor Red
    } else {
        try {
            $DCs | % { Disable-ADAccount -Identity $Identity -ErrorAction Stop -Server $_ }
            Write-Host "Account disabled" -ForegroundColor Green
            Write-Note -Identity $Identity -Option 4 -ConfirmNote "y" -TicketNumber $TicketNumber
        } catch {
            Write-Warning $_
        }
    }
}

# Main function
function Terminator {
    # param($Identity)

    Write-Host "Please provide a user name to retire:"
    $Identity = Select-User
    $TickerNumber = Read-Host "Please provide the ticket number"
    Write-Host "`nThe script will retire the user account as below"
    Write-Host "-------------------------------------------------------------------------------------------------------"
    Write-Host "`n1. Remove all AD Group Membership from the user"
    Write-Host "2. Hide the user from GAL (Global Address List)"
    Write-Host "3. Hide the user's Forget Password in IDM"
    Write-Host "4. Reset password"
    Write-Host "5. Disable the AD account`n"

    $ConfirmTermination = Read-Host "Press any key to proceed"

    Write-Host "-----------------------------" -ForegroundColor Magenta
    Write-Host "Remove all groups" -ForegroundColor Magenta
    Write-Host "-----------------------------" -ForegroundColor Magenta
    Remove-AllGroups -Identity $Identity -TicketNumber $TickerNumber

    Write-Host "-----------------------------" -ForegroundColor Magenta
    Write-Host "Hide from address list" -ForegroundColor Magenta
    Write-Host "-----------------------------" -ForegroundColor Magenta
    Hide-FromAddressLists -Identity $Identity

    Write-Host "-----------------------------" -ForegroundColor Magenta
    Write-Host "Reset password" -ForegroundColor Magenta
    Write-Host "-----------------------------" -ForegroundColor Magenta
    Reset-Password -Identity $Identity

    Write-Host "-----------------------------" -ForegroundColor Magenta
    Write-Host "Hide the user forget password" -ForegroundColor Magenta
    Write-Host "-----------------------------" -ForegroundColor Magenta
    Hide-ForgetPassword -Identity $Identity

    Write-Host "-----------------------------" -ForegroundColor Magenta
    Write-Host "Disable the user account" -ForegroundColor Magenta
    Write-Host "-----------------------------" -ForegroundColor Magenta
    Disable-UserADAccount -Identity $Identity -TicketNumber $TickerNumber

    Write-Host "The user account is terminated" -ForegroundColor Red -BackgroundColor Green

}

Clear-Host
Terminator