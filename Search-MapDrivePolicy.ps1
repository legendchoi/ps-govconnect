function SearchBy-DriveLetter {
    param ($DriveLetter)
    H:\Scripts\Get-GPPDriveMaps.ps1 | ? { $_.DriveLetter -like "$DriveLetter*" }
}

function SearchBy-NetPath {
    param ($Path)
    H:\Scripts\Get-GPPDriveMaps.ps1 | ? { $_.DrivePath -like "*$Path*" }
}


# SearchBy-DriveLetter G

SearchBy-NetPath -Path "\\Vfilerdfs\OFS-FT-CL-Group"



$DFG = (SearchBy-NetPath -Path "\\VFILERDFS\OFS-FT-HBS-GROUP").DriveFilterGroup
$DFG | % { (get-adgroupmember $_.split('\')[1]).name }

Get-ADGroupMember "GOVNET Map Drive G OFS-SIS Group CIFS"