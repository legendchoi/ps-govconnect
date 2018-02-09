<#
Letter Service 
v1.1
#>

# OLD
<# function Get-LetterNewUser {
    [CmdletBinding()]
	param ($Identity, $Password, $SAPID, $Email)

    $UserFullName = Get-ADUser -Identity $Identity -Properties DisplayName | select-object -expandproperty DisplayName

	$Header = "Dear Customer,"
    $Body   = "Thank you for contacting GovConnect Service Desk."
    $Body  += "`r`n`r`nThe account for $UserFullName has been provisioned and account details are below."
    $Body  += "`r`nUsername: $Identity`r`nPassword: $Password`r`nEmployee ID (Used for Verification): $SAPID`r`nEmail: $Email"
    $Body  += "`r`n`r`nThe above username and password applies to SAP/ESS access as well."
    $Body  += "`r`nFor step by step instructions for Self Password Registration and Reset, please follow the below Knowledge Base articles available on GovConnect Portal. You may simply search the respective article ID's provided below."
    $Body  += "`r`nIdentity Portal - Self Service Password Reset - K98135430`r`nIdentity Portal - Forgotten Password Registration - K44553411`r`nIdentity Portal - Password Reset Externally - K44540245"
    $Footer = "`r`nRegards,`r`nGovConnect Service Desk`r`nPhone: 1800 217 640`r`nPortal: https://portal.govconnect.nsw.gov.au"

    $Comment = "`r`nNetwork Account Provisioned for: $UserFullName`r`nCredentials Sent to : "

    $Letter = "$Header`r`n`r`n$Body`r`n$Footer`r`n$Comment"
    
    return $Letter
} #>

function Get-LetterNewUser {
    [CmdletBinding()]
	param ($Identity, $Manager, $Password, $SAPID, $Email)

    $UserFullName = Get-ADUser -Identity $Identity -Properties DisplayName | select-object -expandproperty DisplayName
    if ($Manager) {
        $ManagerFullName = Get-ADUser -Identity $Manager -Properties DisplayName | select-object -expandproperty DisplayName
        $ManagerGivenName = Get-ADUser -Identity $Manager -Properties GivenName | select-object -expandproperty GivenName
    } else {
        $ManagerGivenName = "Customer"
    }
    
	$Header = "Dear $ManagerGivenName,"
    
    $Body   = "Thank you for contacting GovConnect Service Desk. The reason you receive this email either because there is a ticket raised under your name or you are appearing as new starter line manager on SAP system. The account for $UserFullName has been provisioned and account details are below."
    # $Body  += "`r`n`r`nThe account for $UserFullName has been provisioned and account details are below."
    $Body  += "`r`nUsername: $Identity`r`nPassword: $Password`r`nEmployee ID (Used for Verification): $SAPID`r`nEmail: $Email"
    $Body  += "`r`n`r`nThe above username and password applies to SAP/ESS access as well."
    $Body  += "`r`nFor step by step instructions for Self Password Registration and Reset, please follow the below Knowledge Base articles available on GovConnect Portal. You may simply search the respective article ID's provided below."
    $Body  += "`r`nIdentity Portal - Self Service Password Reset - K98135430`r`nIdentity Portal - Forgotten Password Registration - K44553411`r`nIdentity Portal - Password Reset Externally - K44540245"
    $Body  += "`r`n`r`nIf you would like to contact the Service Desk about this Request, please access the portal (https://portal.govconnect.nsw.gov.au/) and use the Chat function, or alternatively please call the Service Desk on 1800 217 640."

    $Footer = "`r`nRegards,`r`nGovConnect Service Desk`r`nPhone: 1800 217 640`r`nPortal: https://portal.govconnect.nsw.gov.au"

    $Comment = "`r`nNetwork Account Provisioned for: $UserFullName`r`nCredentials Sent to : $ManagerFullName"

    $Letter = "$Header`r`n`r`n$Body`r`n$Footer`r`n$Comment"
    
    return $Letter
}




function Get-AccCompLetter {

    param ([string]$SeedFile = "H:\Scripts\seed.csv")
    
    <#
    Format of seed.txt
    0 TICKETNO
    1 SAPNUMBER
    2 USERID
    3 PASSWORD
    4 FIRST.LAST@EMAIL.NSW.GOV.AU
    5 USERFIRSTNAME USERLASTNAME
    6 MANAGERFIRSTNAME MANAGERLASTNAME
    #>

    BEGIN {
        $text = Get-Content -Path $SeedFile
        # $text[0]
    }
    PROCESS {
        $TicketNo = $text[0].Split(",")[1]
        $SAPNo = $text[1].Split(",")[1]
        $UserID = ($text[2].Split(",")[1]).Trim()
        $Password = $text[3].Split(",")[1]
        $EmailAddress = $text[4].Split(",")[1]
        $UserFullName = $text[5].Split(",")[1]
        $ManagerFullName = $text[6].Split(",")[1]
        
        $uidfilter = "(uid=$UserID)"
        $sapfilter = ""
        $ldapentry = Get-LDAPConnectionEntry
        $query = New-Object System.DirectoryServices.DirectorySearcher($ldapentry,$uidfilter)
        $EmailAddressFromSAP = $query.FindAll().properties['mail']
        # $EmailAddressFromAD = (Get-ADUser $UserID -Properties emailaddress).emailaddress.toString()
        $EmailAddressFromAD = Get-ADUserEmailAddress -UserID $UserID
        # (Get-ADUser $UserID -Properties emailaddress).emailaddress.toString()

        # $EmailAddress
        # $EmailAddressFromSAP
        # $EmailAddressFromAD

        # if ($EmailAddress -ne "") {$EmailAddress = $EmailAddress}
        if ($EmailAddress -eq "" -and $EmailAddressFromSAP -ne $null) {$EmailAddress = $EmailAddressFromSAP}
        if (($EmailAddress -eq "" -and $EmailAddress -eq $null) -and $EmailAddressFromAD -ne $null) {$EmailAddress = $EmailAddressFromAD}
        if ($EmailAddress -ne "" -or $EmailAddress -ne $null) {$EmailAddress = "Email: $EmailAddress"} # else {echo "Email is Null"}
        $today = Get-date -Format "dd-MMM-yyy"
        # In case 
        $UserID = $UserID.Trim()
		$UserFullName = Get-ADUser -Identity $UserID -Properties DisplayName -ErrorAction Stop | select-object -expandproperty DisplayName
        $ManagerFirstName = $ManagerFullName.Split(" ")[0]
        Write-Host "`n[LETTER BODY]" -ForegroundColor Yellow
        $body = "Dear $ManagerFirstName,`
        `nThank you for contacting GovConnect Service Desk. The account for $UserFullName has been provisioned and account details are below.`
        `nUsername: $UserID`nPassword: $Password`nEmployee ID (Used for Verification): $SAPNo`n$EmailAddress`
        `nThe above username and password applies to SAP/ESS access as well.`
        `nFor step by step instructions for Self Password Registration and Reset, please follow the below Knowledge Base articles available on GovConnect Portal. You may simply search the respective article ID's provided below.`
        `nIdentity Portal - Self Service Password Reset - K98135430`nIdentity Portal - Forgotten Password Registration - K44553411`nIdentity Portal - Password Reset Externally - K44540245"
        $footer = "`nKind Regards,`nHyun (Jack)`nGovConnect Service Desk`nDirect: 1300 666 277- Ext.3023 (To be used in regards to the above Incident/Request only)`nPortal: https://portal.govconnect.nsw.gov.au"

        Write-Host "$body`n$footer"

        Write-Host "`n[NOTE]" -ForegroundColor Yellow
        $Note = "Account Provision Request: $TicketNo /$today"
        $Note

        Write-Host "`n[REMEDY COMMENT]" -ForegroundColor Yellow
        $RemedyNote = "Network Account Provisioned for: $UserFullName`nCredentials Sent to : $ManagerFullName"
        $RemedyNote

        Write-Host ""
        $ConfirmNote = Read-Host "Appending a note in $UserFullName's Telephone Tab? (y/n)"
        if ($ConfirmNote -eq "y" -or $ConfirmNote -eq "Y") {
            $Info = Get-ADUser $UserID -Properties info | %{ $_.info}
            try {
                Set-ADUser $UserID -Replace @{info="$($Info) `r`n $Note"} -ErrorAction Stop
                Write-Host "Note Added" -ForegroundColor Green
            } catch {
                Write-Error $_
            }            
        }
    }
    END {}

}