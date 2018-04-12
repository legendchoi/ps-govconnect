Write-Output "Please, provide AD User ID"

$src_user = Read-Host 'Copy From: '
$dst_user = Read-Host 'Copy to: '
$src_user_name = Get-ADUser -Identity $src_user -Properties DisplayName | select-object -expandproperty DisplayName
$dst_user_name = Get-ADUser -Identity $dst_user -Properties DisplayName | select-object -expandproperty DisplayName

Write-host "`nCopying user group from $src_user_name to $dst_user_name"

#Copy groups
Get-ADUser -Identity $src_user -Properties memberof | 
	Select-Object -ExpandProperty memberof | 
	Add-ADGroupMember -Members $dst_user -PassThru | 
	Select-Object -Property SamAccountName

#H Drive configuration
$h_drive = Read-Host 'Do you want to setup H Drive? [y/n] Enter'

if ($h_drive -eq 'y' -Or $h_drive -eq 'Y') {
    $path = Get-ADUser -Identity $src_user -Properties HomeDirectory | Select-Object -expandproperty HomeDirectory
    $path = $path -replace "$src_user", "$dst_user"
    set-aduser $dst_user -homedirectory "$path" -homedrive h:
    Write-Output "`nH: Drive created successfully!"
    Get-ADUser -Identity $dst_user -Properties HomeDirectory | Select-Object -expandproperty HomeDirectory

} else {
	Write-Output "`nGood Bye! ^__^"
}