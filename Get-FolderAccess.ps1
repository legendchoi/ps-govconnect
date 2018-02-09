# v0.2

. "$PSScriptRoot\Includes\Functions.ps1"

function Assign-FolderAccess {
    param($Identity, $AccessGroupFolder)

    # Write-Host "Test1: $AccessGroupFolder"
    $ct = $AccessGroupFolder.count
    # Write-Host "Test2: $ct"

    Write-Host 
    do {
        $repeat=$false
        $choices = Read-host "Please select the security group or groups separated by comma(,) for a folder access"
        if (!$choices) {
            Write-Host "The selection is null. Please try again" -ForegroundColor Red
            $repeat=$true
        } else {
            $str = $choices.replace(",","")
            $checknum = $str -imatch "[a-z]"
            if ($checknum) {
                Write-Host "The selection contains none numeric value. Please try again." -ForegroundColor Red
                $repeat=$true
            } else {
                $groups = $choices.Split(',').Trim()


                

                $addgroups=@()
                foreach ($group in $groups) {

                    if ($ct -eq 1) {
                        $addgroups = $AccessGroupFolder
                    } else {
                        $addgroups += ,$AccessGroupFolder[$group-1]
                    }
                    
                    # add-group -identity $identity -group
                }
                $addgroups
                $continue = Read-Host "Do you wish to continue? (Y/n)"
                if($continue -ieq 'y'){
                    Add-Groups -Identity $Identity -Groups $addgroups
                }else{
                    write-host "cancelled" -ForegroundColor Red
                }
            }
        }
    }while($repeat)
}


function Select-RootServer {
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 

    $objForm = New-Object System.Windows.Forms.Form 
    $objForm.Text = "Select a Computer"
    $objForm.Size = New-Object System.Drawing.Size(300,200) 
    $objForm.StartPosition = "CenterScreen"


    $objForm.KeyPreview = $True
    $objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") 
        {$x=$objListBox.SelectedItem;$objForm.Close()}})
    $objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") 
        {$objForm.Close()}})

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Size(75,120)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "OK"
    $OKButton.Add_Click({$x=$objListBox.SelectedItem;$objForm.Close()})
    $objForm.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Size(150,120)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = "Cancel"
    $CancelButton.Add_Click({$objForm.Close()})
    $objForm.Controls.Add($CancelButton)

    $objLabel = New-Object System.Windows.Forms.Label
    $objLabel.Location = New-Object System.Drawing.Size(10,20) 
    $objLabel.Size = New-Object System.Drawing.Size(280,20) 
    $objLabel.Text = "Please select a root server:"
    $objForm.Controls.Add($objLabel) 

    $objListBox = New-Object System.Windows.Forms.ListBox 
    $objListBox.Location = New-Object System.Drawing.Size(10,40) 
    $objListBox.Size = New-Object System.Drawing.Size(260,20) 
    $objListBox.Height = 80

    [void] $objListBox.Items.Add("\\vfilerdfs")
    [void] $objListBox.Items.Add("\\Vfilerdpc")
    [void] $objListBox.Items.Add("\\Vfilertsy")
    [void] $objListBox.Items.Add("\\VFILERDFS-SF")
    [void] $objListBox.Items.Add("\\NEWCWFS01")
    # [void] $objListBox.Items.Add("\\VFILERDFS-SF")
    # [void] $objListBox.Items.Add("atl-dc-003")
    # [void] $objListBox.Items.Add("atl-dc-004")
    # [void] $objListBox.Items.Add("atl-dc-005")
    # [void] $objListBox.Items.Add("atl-dc-006")
    # [void] $objListBox.Items.Add("atl-dc-007")

    $objForm.Controls.Add($objListBox) 

    $objForm.Topmost = $True

    $objForm.Add_Shown({$objForm.Activate()})
    [void] $objForm.ShowDialog()

    return $objListBox.SelectedItem
}


Function Select-FolderDialog {
    # param([string]$Description="Select Folder",[string]$RootFolder="Desktop")
    param([string]$Description="Select Folder",[string]$RootFolder)

    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $objForm = New-Object System.Windows.Forms.FolderBrowserDialog
    # $objForm.Rootfolder = $RootFolder
    $objForm.SelectedPath = $RootFolder
    $objForm.Description = $Description
    $objForm.showNewFolderButton = $false
    $Show = $objForm.ShowDialog()
    If ($Show -eq "OK") {
        Return $objForm.SelectedPath
    } Else {
        Write-Error "Operation cancelled by user."
    }
}

<#
$RootFolder = Select-RootServer
$folder = Select-FolderDialog -RootFolder $RootFolder
$folder
#>




# Main
Clear-Host

Write-Host "#############################################"
Write-Host "########## Resolving Network Drive ##########"
Write-Host "#############################################"
$Identity = Select-User
Write-Host "Searching for Map drive(s) for the user. Please wait..." -ForegroundColor DarkGreen

$UserSecurityGroups = (get-aduser $Identity -Properties memberof).memberof | % {([regex]::split($_,'^CN=|,.+$'))[1]}

Write-Host "[GPO View]" -ForegroundColor Cyan

$MapDriveSecurityGroupList = $UserSecurityGroups | ? {$_ -match "Map Drive|Users|File" -and $_ -notmatch "Domain Users|Mobility|Cisco|^DL|Condeco" } |
                % {(Get-ADGroup $_ -Properties memberof).memberof | % {([regex]::split($_,'^CN=|,.+$'))[1]}} |
                Sort-Object | Get-Unique -AsString | ? { $_ -imatch "Map Drive|File" }
foreach ($MapDriveSecurityGroup in $MapDriveSecurityGroupList) { 
    ."$PSScriptRoot\Get-GPPDriveMaps.ps1" | Where-Object {$_.DriveFilterGroup -imatch $MapDriveSecurityGroup} | ft DriveLetter, DrivePath -auto 
}
Write-Host "Note: Please ignore redundant drive letter if presented. They are identical." -ForegroundColor DarkGreen

Write-Host "[Registry View]" -ForegroundColor Cyan
Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" # Import the ConfigurationManager.psd1 module 
Set-Location "P01:" # Set the current location to be the site code.
$computers = (Get-CMUserDeviceAffinity -UserName "govnet\$identity").ResourceName
Set-Location h:
$sid=(Get-ADUser $identity).SID.Value
$keypath = "$sid\Network"

$hkeytype = [Microsoft.Win32.RegistryHive]::Users

foreach ($Computer in $computers) {
    Write-Host "Computer Name: $Computer" -ForegroundColor Yellow
    
    if (Test-Connection -ComputerName $Computer -count 1 -ea 0) {
        $basekey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hkeytype,$computer)
        $subkey = $basekey.OpenSubKey($keypath,$true)
        $subkeynames = $subkey.GetSubKeyNames()

        foreach ($subkeyname in $subkeynames) {
            Write-Host "Drive $subkeyname : " -NoNewline
            $newkeypath = $keypath+"\$subkeyname"
            $newsubkey = $basekey.OpenSubKey($newkeypath,$true)
            $newsubkey.GetValue("RemotePath")
        }
    } else {
        Write-Host "$computer is not responding. Possibly it is not online" -ForegroundColor Red
    }

} # foreach



Write-Host "`nPlease provide the full path of the shared folder which you'd like to get the user an access."

<#
do {
    $repeat=$false
    $TargetPath = (Read-Host "Path in UNC format (eg. \\server\path\to\folder)").Trim()
    $targetPath
    Test-Path $TargetPath
    if (!$TargetPath) {
        Write-Host "UNC is null" -ForegroundColor Red
        $repeat=$true
    } else {
        Write-Host "Checking the path. Please wait..." -ForegroundColor DarkGreen
        if(Test-Path $TargetPath) {
            $repeat=$false
        } else {
            Write-Host "The path does not exist. Check the path and try again." -ForegroundColor Red
            $repeat=$true
        }
    }
}while($repeat)
#>

do {
    $repeat=$false
    # $TargetPath = (Read-Host "Path in UNC format (eg. \\server\path\to\folder)").Trim()
    $RootFolder = Select-RootServer
    $TargetPath = Select-FolderDialog -RootFolder $RootFolder
    $TargetPath
    Test-Path $TargetPath
    if (!$TargetPath) {
        Write-Host "UNC is null" -ForegroundColor Red
        $repeat=$true
    } else {
        Write-Host "Checking the path. Please wait..." -ForegroundColor DarkGreen
        if(Test-Path $TargetPath) {
            $repeat=$false
        } else {
            Write-Host "The path does not exist. Check the path and try again." -ForegroundColor Red
            $repeat=$true
        }
    }
}while($repeat)





$SecGroups = (Get-Acl "FileSystem::$TargetPath").Access | ? {$_.IdentityReference -notmatch "NT AUTHORITY|BUILTIN|Systems Admins|Systems ContactCentre|^S-1-|_svc"} | sort FileSystemRights
# $SecGroups | ft IdentityReference, FileSystemRights -Autosize

# Write-Host "########### List the available Access Security Group for the folder ###############"
Write-Host "[File Access Security Groups - Folder]" -ForegroundColor Yellow
$Number = 1
$SecGroups | ForEach-Object {New-Object psObject -Property @{'Number'=$Number;'IdentityReference'= $_.IdentityReference;'FileSystemRights'=$_.FileSystemRights};$Number ++} |
    ft Number, IdentityReference, @{n="FileSystemRights";e={$_.FileSystemRights};align="left"} -AutoSize | Out-Host



# Take out 'GOVNET\' word
$AccessGroupFolder = $SecGroups.IdentityReference.value.toupper().replace("GOVNET\", "").replace("GOVNET ","")
$AccessGroupUser = (Get-ADPrincipalGroupMembership $Identity | ? {$_.name -imatch "^file|MIG-" }).name
# echo "TEST"
$AccessGroupUser = $UserSecurityGroups | ? {$_ -imatch "^file|MIG-"}

# Compare if the user already have the folder access
$a = $AccessGroupFolder | sort # Folder
$b = $AccessGroupUser | sort # Users

<#
Write-Host "[File Access Groups - Folder]" -ForegroundColor Yellow
$a
#>
Write-Host "[File Access Security Groups - User]" -ForegroundColor Yellow

if($b){
    $b
    Write-Host "`n[Matched groups]" -ForegroundColor Yellow
    $c = (Compare-Object $a $b -IncludeEqual -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | ? {$_.SideIndicator -eq "=="}).InputObject
    if ($c) {
        # Write-Host "Match found" -ForegroundColor Green
        # write-Host $c -ForegroundColor Green
        $c | % {write-host $_ -ForegroundColor Green}
    } else {
        Write-Host "Null" -foregroundcolor Red
        # Assign-FolderAccess -Identity $Identity -AccessGroupFolder $AccessGroupFolder
    }
}else{
    Write-Host "The user do not have any security group membership for a file access" -foregroundcolor red
    # Assign-FolderAccess -Identity $Identity -AccessGroupFolder $AccessGroupFolder
}


$continue = Read-Host "`nDo you still need to assign security group(s) to the user? (Y/n)"
if ($continue -ieq 'y') {
    Assign-FolderAccess -Identity $Identity -AccessGroupFolder $AccessGroupFolder
} else {
    Write-Host "Cancelled" -ForegroundColor Red
}


# $c = $null

# sample path and users
# $TargetPath = "\\vfilerdfs\OFS-TA-Group\Business Units\PMO\Project Repository\NSWTA115S_O & M Transformation Program"
# $TargetPath = "\\vfilerdfs\OFS-TA-Group\Business Units\PMO\Project Repository"
# $TargetPath = "\\vfilerdfs\OFS-TA-Group\Business Units\PMO"
# \\vfilerdfs\OFS-TA-Group\Business Units
# \\vfilerdfs\OFS-TA-Group\Business Units\PMO\Project Repository\NSWTA115S_O & M Transformation Program

# Daniel Roelink
# Ajit Narayan
# Rami Hourani
# Christian Chillari
# Brad Pointing