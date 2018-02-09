<#
Letter Service 
v0.3
#>

."$PSScriptRoot\Get-ExtNumber.ps1"

function Get-LetterNewUser {
    [CmdletBinding()]
	param ($Identity, $Manager, $Password, $SAPID, $Email)

    $AgentName = $env:USERNAME
    $AgentDisplayName = (Get-ADUser $AgentName -Properties DisplayName).DisplayName
    $AgentExtNumber = Get-ExtNumber

    $UserFullName = Get-ADUser -Identity $Identity -Properties DisplayName | select-object -expandproperty DisplayName
    if ($Manager) {
        $ManagerFullName =  Get-ADUser -Identity $Manager -Properties DisplayName | select-object -expandproperty DisplayName
        $GivenName =        Get-ADUser -Identity $Manager -Properties GivenName | select-object -expandproperty GivenName
        $ManagerGivenName = $GivenName.SubString(0,1).ToUpper()+$GivenName.SubString(1).ToLower()
    } else {
        $ManagerGivenName = "Customer"
    }
    
	$Header = "Dear $ManagerGivenName,"
    
    $Body   = "Thank you for contacting GovConnect Service Desk. The reason you receive this email either because there is a ticket raised under your name or you are appearing as new starter line manager on SAP system. The account for $UserFullName has been provisioned and account details are below."
    # $Body  += "`r`n`r`nThe account for $UserFullName has been provisioned and account details are below."
    $Body  += "`r`n - Username: $Identity`r`n - Password: $Password`r`n - Employee ID (Used for Verification): $SAPID`r`n - Email: $Email"
    $Body  += "`r`n`r`nThe above username and password applies to SAP/ESS access as well."
    $Body  += "`r`nFor step by step instructions for Self Password Registration and Reset, please follow the below Knowledge Base articles available on GovConnect Portal. You may simply search the respective article ID's provided below."
    $Body  += "`r`n - Identity Portal - Self Service Password Reset - K98135430`r`n - Identity Portal - Forgotten Password Registration - K44553411`r`n - Identity Portal - Password Reset Externally - K44540245"
    $Body  += "`r`n`r`nIf you would like to contact the Service Desk about this Request, please access the portal (https://portal.govconnect.nsw.gov.au/) and use the Chat function, or alternatively please call the Service Desk on 1800 217 640."

    # $Footer = "`r`nRegards,`r`nGovConnect Service Desk`r`nPhone: 1800 217 640`r`nPortal: https://portal.govconnect.nsw.gov.au"
    $Footer = "`r`n`r`nKind Regards,`r`n`r`n$AgentDisplayName`r`nGovConnect Service Desk`r`nPhone: 1800 217 640`r`nDirect:1300 666 277 ext#$AgentExtNumber (To be used in regards to the above Incident/Request only)`r`nPortal: https://portal.govconnect.nsw.gov.au"

    $Comment = "`r`nNetwork Account Provisioned for: $UserFullName`r`nCredentials Sent to            : $ManagerFullName"

    $Letter = "$Header`r`n`r`n$Body`r`n$Footer`r`n$Comment"
    # $letter | Out-File Letter-NonIT.txt
    # Notepad Letter-NonIT.txt
    
    return $Letter
}


# Write Network Access Privilege Change Letter
Function Write-NAPCLetter {
    [CmdletBinding()]
    Param ($TargetUser,$RefUser)
    # Param ($TargetUserName,$RefUserName)
    
    $TargetUserName = (Get-ADUser $TargetUser -Properties DisplayName).DisplayName
    $RefUserName = (Get-ADUser $RefUser -Properties DisplayName).DisplayName

    $TargetUserGivenName = (Get-ADUser $TargetUser).GivenName
    $TargetUserEmail = (Get-ADUser $TargetUser).UserPrincipalName

    $AgentName = $env:USERNAME
    $AgentDisplayName = (Get-ADUser $AgentName -Properties DisplayName).DisplayName
    $AgentExtNumber = Get-ExtNumber



    $Header = "Dear [Customer] ,"

    $Body  =  "`r`n`r`nThank you for contacting GovConnect Service Desk."
    $Body  += "`r`n`r`nPlease be advised that requested additional group(s) have been added to $TargetUserName to allow access to/same as $RefUserName."
    $Body  += "`r`n`r`nPlease restart the computer first to allow changes to take effect."
    # $Footer = "`r`nRegards,`r`nGovConnect Service Desk`nPhone: 1800 217 640`r`nPortal: https://portal.govconnect.nsw.gov.au"
    $Footer = "`r`n`r`nKind Regards,`r`n`r`n$AgentDisplayName`r`nGovConnect Service Desk`r`nPhone: 1800 217 640`r`nDirect: 1300 666 277 ext#$AgentExtNumber (To be used in regards to the above Incident/Request only)`r`nPortal: https://portal.govconnect.nsw.gov.au"
    $Info = "`r`n`r`n`r`n`r`nTarget User Info`r`nUser Name: $TargetUserName`r`nEmail: $TargetUserEmail"
    return ($Header+$Body+$Footer+$Info)
}


# Write Shared Mailbox Letter - in progress
function Write-SMLetter {
    param($UserName, $EmailBoxName, $Access)
    # $ConfirmLetter = Read-Host "Print a letter? (y/n)"
    $ConfirmLetter = 'y'
    if ($ConfirmLetter -ieq "y") {
        $EmailBoxAddress =  (Get-Mailbox -Identity $EmailBoxName | Select-Object PrimarySmtpAddress).PrimarySmtpAddress
        # $EmailBoxName =     (Get-Mailbox -Identity $EmailBoxName | Select-Object Alias).Alias
        $UserFullName =     Get-ADUser -Identity $UserName -Properties DisplayName | select-object -expandproperty DisplayName

        $Today = Get-Date -Format "dd-MMM-yyyy"
        $AgentName = $env:USERNAME
        $AgentDisplayName = (Get-ADUser $AgentName -Properties DisplayName).DisplayName
        $AgentExtNumber = Get-ExtNumber

        $Header = "Dear ********* ,"

        $AddBothAccess =                "`r`nFull Access and Send As access has been provided to $UserFullName for mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $DelBothAccess =                "`r`nFull Access and Send As access has been removed from $UserFullName for mailbox(s): $EmailBoxAddress.`n`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $AddFullSendOnBehalfAccess =    "`r`nFull Access and Send on behalf access has been provided to $UserFullName for mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $DelFullSendOnBehalfAccess =    "`r`nFull Access and Send on behalf access has been removed from $UserFullName for mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $AddFullAccess =                "`r`n$UserFullName has been provided Full Access to mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $DelFullAccess =                "`r`n$UserFullName has been removed Full Access from mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $AddSendAsAccess =              "`r`n$UserFullName has been provided SendAs Access to mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $DelSendAsAccess =              "`r`n$UserFullName has been removed SendAs Access from mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $AddSendOnBehalfAccess =        "`r`n$UserFullName has been provided Send on behalf access to mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"
        $DelSendOnBehalfAccess =        "`r`n$UserFullName has been removed Send on behalf access from mailbox(s): $EmailBoxAddress.`r`n`r`nPlease wait for 15-30 minutes. After that, close and re-open outlook to allow changes to take effect.`n"

        $Footer = "`r`nKind Regards,`r`n`r`n$AgentDisplayName`r`nGovConnect Service Desk`r`nPhone: 1800 217 640`r`nDirect:1300 666 277 ext#$AgentExtNumber (To be used in regards to the above Incident/Request only)`r`nPortal: https://portal.govconnect.nsw.gov.au"

        $Header | Out-File Letter.txt
        Switch ($Access) {
            'addfull'       { $AddFullAccess          | Out-File Letter.txt -Append }
            'addsendas'     { $AddSendAsAccess        | Out-File Letter.txt -Append }
            'addfullsendas' { $AddBothAccess          | Out-File Letter.txt -Append }
            'delfull'       { $DelFullAccess          | Out-File Letter.txt -Append }
            'delsendas'     { $DelSendAsAccess        | Out-File Letter.txt -Append }
            'delfullsendas' { $DelBothAccess          | Out-File Letter.txt -Append }
            'addsendon'     { $AddSendOnBehalfAccess  | Out-File Letter.txt -Append }
            'delsendon'     { $DelSendOnBehalfAccess  | Out-File Letter.txt -Append }
            'addfullsendon' { $AddFullSendOnBehalfAccess | Out-File Letter.txt -Append }
            'delfullsendon' { $DelFullSendOnBehalfAccess | Out-File Letter.txt -Append }
            default {Write-Host "Error"}

            # 7 # Set-SendOnBehalf
            # 8 # Remove-SendOnBehalf
            # 9 # Set-Both (Full & SendOnBehalf)
            # 0 # Remove-Both (Full & SendOnBehalf)
        }
        $Footer | Out-File Letter.txt -Append
        Notepad Letter.txt
        Write-Host "Letter printed" -ForegroundColor Green
    } else {
        Write-Host "Letter cancelled"
    }
}
