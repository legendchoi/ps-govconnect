$myName = Read-Host "Name"
$normalizedName = (Get-Culture).TextInfo.ToTitleCase($myName)

$normalizedName

$givenname = $givenname.substring(0,1).toupper()+$givenname.substring(1).tolower()   


Get-ADUser choih -Properties TerminalServicesProfilePath | Select-Object -ExpandProperty TerminalServiceProfilePath


$ou = [adsi]"$($OU)"
$user = $ou.psbase.get_children().find($DN)

$user.psbase.invokeSet("allowLogon",1)
$user.psbase.invokeSet("TerminalServicesHomeDirectory","$($HomeDirPathValue)")
$user.psbase.invokeSet("TerminalServicesProfilePath","$($ProfileDirPathValue)")
$user.psbase.invokeSet("TerminalServicesHomeDrive",$HomeDriveValue)
$user.setinfo()

$userDN = (Get-ADUser choih).distinguishedName
$userInfo = [ADSI]"LDAP://$userDN"
$userInfo.TerminalServicesHomeDirectory
$userInfo.TerminalServicesHomeDrive
if($userInfo.TerminalServicesProfilePath) {
    write-host "Not Null"
} else {
    Write-Host "Null"
}

$userInfo | select Name, AllowLogon, TerminalServicesProfilePath, TerminalServicesHomeDirectory, TerminalServicesHomeDrive | fl



# $userInfo.TerminalServicesHomeDirectory = "\\dc1wfs01\home\CHOIH"
# $userInfo.TerminalServicesHomeDrive = "N:"

$UserInfo.psbase.invokeset("TerminalServicesHomeDrive","N:")
$UserInfo.psbase.invokeset("TerminalServicesHomeDirectory","\\dc1wfs01\home\CHOIH")

# $UserInfo.psbase.invokeset("TerminalServicesHomeDrive","$null")
# $UserInfo.psbase.invokeset("TerminalServicesHomeDirectory","$null")

$UserInfo.setinfo()

# $user.terminalServicesHomeDirectory = "Y:\RDS"
# How to set
# $user.setinfo()

Get-ADUser -Identity choih -Properties HomeDirectory -ErrorAction Stop | Select-Object -ExpandProperty HomeDirectory




# $userInfo.employeeID
$userInfo.psbase.invokeget("TerminalServicesProfilePath")
$userInfo.TerminalServicesProfilePath

(Get-ADUser choih).distinguishedName


