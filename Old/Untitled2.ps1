#------------------------------
# AD Group

Get-ADGroup -Filter {Name -like "CTX*"}



#--------------------------------
# Distriburion Group

Get-DistributionGroup -Identity "DL CMO*"
Get-DistributionGroup -Identity "DL Office of the Sec - SPPMO - All"


Add-ADPermission -Identity "DL CMO Team" -User schofiel -AccessRights ReadProperty, WriteProperty -Properties Member
Add-ADPermission -Identity "DL Office of the Sec - SPPMO - All" -User schofiel -AccessRights ReadProperty, WriteProperty -Properties Member

Get-ADUser schofiel




https://sbl.uat.onegov.nsw.gov.au/glsuat
