Set-Location "H:"

# APP MS Office 365 Project Pro C2R
$ProjectUserList = "H:\ProjectUsers.txt"
$ProjectUserListGood = "H:\ProjectUsers-good.txt"
if (!(Test-Path $ProjectUserListGood)) {New-Item -Path h:\ -Name ProjectUsers-good.txt -ItemType "file";Write-Host "File created" }
$ProjectUserListBad = "H:\ProjectUsers-bad.txt"
if (!(Test-Path $ProjectUserListGood)) {New-Item -Path h:\ -Name ProjectUsers-bad.txt -ItemType "file";Write-Host "File created" }
$ProjectFiltered = @()
$ProjectUsers = Get-Content $ProjectUserList
$ProjectUsers | % {
    $userid = $_.trim()
    try {
        (Get-ADUser $userid).name
        Add-Content $ProjectUserListGood $userid
        $ProjectFiltered += $userid
    } catch {
        write-Host "$userid - not found" -ForegroundColor Red
        Add-Content $ProjectUserListBad $userid
    }
}

# $ProjectFiltered
$ProjectFiltered | %{ Add-ADGroupMember -Identity "APP MS Office 365 Visio Pro C2R" -Members $_ }




$SiteCode = "P01" 
$SiteServer = "DC1WCM01.govnet.nsw.gov.au" 
 
# ----------------------------------------------------------------------------- 
 
# Import the ConfigurationManager.psd1 module  
Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"  
 
# Set the current location to be the site code. 
Set-Location $SiteCode":\"  
 
# ----------------------------------------------------------------------------- 
 
Function Update-CMUserCollection 
{ 
    <# 
    .Synopsis 
       Update SCCM Device Collection 
    .DESCRIPTION 
       Update SCCM Device Collection. Use the -Wait switch to wait for the update to complete. 
    .EXAMPLE 
       Update-CMDeviceCollection -DeviceCollectionName "All Workstations" 
    .EXAMPLE 
       Update-CMDeviceCollection -DeviceCollectionName "All Workstations" -Wait -Verbose 
    #> 
 
    [CmdletBinding()] 
    [OutputType([int])] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true, 
                   Position=0)] 
        $UserCollectionName, 
        [Switch]$Wait 
    ) 
 
    Begin 
    { 
        Write-Verbose "$UserCollectionName : Update Started" 
    } 
    Process 
    { 
        $Collection = Get-CMUserCollection -Name $UserCollectionName 
        $null = Invoke-WmiMethod -Path "ROOT\SMS\Site_$($SiteCode):SMS_Collection.CollectionId='$($Collection.CollectionId)'" -Name RequestRefresh -ComputerName $SiteServer
    } 
    End 
    { 
        if($Wait) 
        { 
            While($(Get-CMUserCollection -Name $UserCollectionName | Select -ExpandProperty CurrentStatus) -eq 5) 
            { 
                Write-Verbose "$UserCollectionName : Updating..." 
                Start-Sleep -Seconds 5 
            } 
            Write-Verbose "$UserCollectionName : Update Complete!" 
        } 
    } 
} 

# Update-CMUserCollection -UserCollectionName "MS Office 365 Visio Pro C2R" -Wait -Verbose
Update-CMUserCollection -UserCollectionName "MS Office 365 Project Pro C2R" -Wait -Verbose