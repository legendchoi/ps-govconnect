Set-Location "H:"
# APP MS Office 2016 x86 ProPlus - Day 1

$coms = Get-Content H:\comp.txt
$bad = "H:\compbad.txt"
$good = "H:\compgood.txt" 
$prelist = (Get-ADGroupMember -Identity "APP MS Office 2016 x86 ProPlus - Day 1").name
$filtered = @()
$coms | %{
    $compid = $_.trim()
    try {
        (Get-ADComputer $compid).name
        <#
        $compname = (Get-ADComputer $compid).name
        if ($prelist -contains $compname) {
            Write-Host "$compname - existed" -ForegroundColor Yellow
            $compid = $compid + " - Duplicated"
        } else {
            Wirte-Host $compname
        }
        #>
        
        Add-Content $good $compid
        $filtered += $compid
    } catch {
        write-Host "$compid - not found" -ForegroundColor Red
        Add-Content $bad $compid
    }
}
# $filtered
$filtered | %{ Add-ADGroupMember -Identity "APP MS Office 2016 x86 ProPlus - Day 1" -members (Get-ADComputer $_)}

# $prelist = (Get-ADGroupMember -Identity "APP MS Office 2016 x86 ProPlus - Day 1").name
# $prelist -contains "R90MW8X2"

$SiteCode = "P01" 
$SiteServer = "DC1WCM01.govnet.nsw.gov.au" 
 
# ----------------------------------------------------------------------------- 
 
# Import the ConfigurationManager.psd1 module  
Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"  
 
# Set the current location to be the site code. 
Set-Location $SiteCode":\"  
 
# ----------------------------------------------------------------------------- 
 
Function Update-CMDeviceCollection 
{  
    [CmdletBinding()] 
    [OutputType([int])] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true, 
                   Position=0)] 
        $DeviceCollectionName, 
        [Switch]$Wait 
    ) 
 
    Begin 
    { 
        Write-Verbose "$DeviceCollectionName : Update Started" 
    } 
    Process 
    { 
        $Collection = Get-CMDeviceCollection -Name $DeviceCollectionName 
        $null = Invoke-WmiMethod -Path "ROOT\SMS\Site_$($SiteCode):SMS_Collection.CollectionId='$($Collection.CollectionId)'" -Name RequestRefresh -ComputerName $SiteServer
    } 
    End 
    { 
        if($Wait) 
        { 
            While($(Get-CMDeviceCollection -Name $DeviceCollectionName | Select -ExpandProperty CurrentStatus) -eq 5) 
            { 
                Write-Verbose "$DeviceCollectionName : Updating..." 
                Start-Sleep -Seconds 5 
            } 
            Write-Verbose "$DeviceCollectionName : Update Complete!" 
        } 
    } 
} 

Update-CMDeviceCollection -DeviceCollectionName "MS Office 2016 x86 ProPlus - Day 1" -Wait -Verbose