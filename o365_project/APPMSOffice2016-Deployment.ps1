# APP MS Office 2016 x86 ProPlus - Day 1

function Get-SMSMembers {
    param ($SiteServer,$SiteCode,$CollectionName)

    # Retrieve SCCM collection by name 
    $Collection = get-wmiobject -ComputerName $siteServer -NameSpace "ROOT\SMS\site_$SiteCode" -Class SMS_Collection | where {$_.Name -eq "$CollectionName"} 
    # Retrieve members of collection 
    $SMSMemebers = Get-WmiObject -ComputerName $SiteServer -Namespace  "ROOT\SMS\site_$SiteCode" -Query "SELECT * FROM SMS_FullCollectionMembership WHERE CollectionID='$($Collection.CollectionID)' order by name" | select Name
    $SMSMemebers = $SMSMemebers.name | % {$_.split(" ")[0].replace("GOVNET\","")}
    return $SMSMemebers
}

function Get-CMStatus {
    param ($CollectionName, $CollectionType)

    if ($CollectionType -ieq "Computer") {
        $status = Get-CMDeviceCollection -Name $CollectionName | Select -ExpandProperty CurrentStatus
    } else {
        $status = Get-CMUserCollection -Name $CollectionName | Select -ExpandProperty CurrentStatus
    }
    return $status
}

Function Update-CMCollection {  
    [CmdletBinding()] 
    [OutputType([int])] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true, 
                   Position=0)] 
        $CollectionName,
        $CollectionType,
        $SiteCode,
        $SiteServer,
        [Switch]$Wait 
    ) 
 
    Begin 
    { 
        Write-Verbose "$CollectionName : Update Started" 
    } 
    Process 
    { 
        if ($CollectionType -ieq "Computer") {
            $Collection = Get-CMDeviceCollection -Name $CollectionName 
        } else {
            $Collection = Get-CMUserCollection -Name $CollectionName
        }
        $null = Invoke-WmiMethod -Path "ROOT\SMS\Site_$($SiteCode):SMS_Collection.CollectionId='$($Collection.CollectionId)'" -Name RequestRefresh -ComputerName $SiteServer
    } 
    End 
    { 
        if($Wait) 
        {         

            While((Get-CMStatus -CollectionName $CollectionName -CollectionType $CollectionType) -eq 5) 
            { 
                Write-Verbose "$CollectionName : Updating..." 
                Start-Sleep -Seconds 5 
            } 
            Write-Verbose "$CollectionName : Update Complete!" 
        } 
    } 
} 


Set-Location "H:"
$DCs = (Get-ADGroupMember 'Domain Controllers').name
$SiteServer = 'DC1WCM01.govnet.nsw.gov.au'
$SiteCode = 'P01'

do {
    Write-Host "1. MS Office 2016 x86 ProPlus - Day 1"
    Write-Host "2. MS Office 2016 x86 ProPlus - Bligh L8"
    Write-Host "3. MS Office 2016 x86 ProPlus - FT Parramatta"
    Write-Host "4. MS Office 365 ProPlus Broad -TSY-PRD"
    Write-Host "5. MS Office 365 Visio Pro C2R"
    Write-Host "6. MS Office 365 Project Pro C2R"
    $Choice = (Read-Host "`nWhat to deploy").Trim()
    switch ($Choice) {
        '1' 
        {
            $CollectionName = 'MS Office 2016 x86 ProPlus - Day 1'
            $GroupName = 'APP MS Office 2016 x86 ProPlus - Day 1'
            $CollectionType = "Computer"
            $InputFileName = "H:\comp.txt"
            Write-Host $GroupName -foreground Yellow
        }
        '2' 
        {
            $CollectionName = 'MS Office 2016 x86 ProPlus - Bligh L8'
            $GroupName = 'APP MS Office 2016 x86 ProPlus - Bligh L8'
            $CollectionType = "Computer"
            $InputFileName = "H:\comp.txt"
            Write-Host $GroupName -foreground Yellow
        }
        '5' 
        {
            $CollectionName = 'MS Office 365 Visio Pro C2R'
            $GroupName = "APP MS Office 365 Visio Pro C2R"
            $CollectionType = "User"
            $InputFileName = "H:\VisioUsers.txt"
            Write-Host $GroupName -foreground Yellow
        }
        '6' 
        {
            $CollectionName = 'MS Office 365 Project Pro C2R'
            $GroupName = "APP MS Office 365 Project Pro C2R"
            $CollectionType = "User"
            $InputFileName = "H:\ProjectUsers.txt"
            Write-Host $GroupName -foreground Yellow
        }
        '3'
        {
            $CollectionName = 'MS Office 2016 x86 ProPlus - FT Parramatta'
            $GroupName = "APP MS Office 2016 x86 ProPlus - FT Parramatta"
            $CollectionType = "Computer"
            $InputFileName = "H:\comp.txt"
            Write-Host $GroupName -foreground Yellow
        }
        '4'
        {
            $CollectionName = 'MS Office 365 ProPlus Broad -TSY-PRD'
            $GroupName = "APP MS Office 2016 x86 ProPlus - TSY-PRD"
            $CollectionType = "Computer"
            $InputFileName = "H:\comp.txt"
            Write-Host $GroupName -foreground Yellow
        }



        default {Write-Host "Wrong Choice. Try again" -foreground Red;$Choice = $null}
    }

} while ($Choice -eq $null)


do {
    $Operation = Read-Host "Adding(a) or Removing(r) - Default(Add)"
    switch ($Operation) {
        ""  { Write-Host "Adding"; $Operation = "Adding" }
        'a' { Write-Host "Adding"; $Operation = "Adding" }
        'A' { Write-Host "Adding"; $Operation = "Adding" }
        "r"  { Write-Host "Removing"; $Operation = "Removing"}
        "R"  { Write-Host "Removing"; $Operation = "Removing"}
        default {Write-Host "Wrong Choice. Try again" -ForegroundColor Red}
    }
} while (($Operation -notmatch "Adding|Removing") -or ($Operation -eq $null) )

# $Operation

# Read-Host "Hold"

# Input Files
$List = Get-Content $InputFileName

# Log File
$LogFile = "H:\Log_SCCM0365Deployment.txt"
if (!(Test-Path $LogFile)) {New-Item -Path h:\ -Name $LogFile -ItemType "file";Write-Host "$LogFile created" }

# Main Operation
$filtered = @()
$GroupMembers = (Get-ADGroupMember -Identity $GroupName).name
# $SMSMemebers  = Get-SMSMembers -SiteServer $SiteServer -SiteCode $SiteCode -CollectionName $CollectionName
$Time = Get-Date -Format "dd-MMM-yyyy HH:mm"

$List | %{
    $Member = $_.trim()
    try {
        # Validating Computer Name
        if ($CollectionType -ieq "Computer") { 
            $MemberName = (Get-ADComputer $Member).name
        } else {
            $MemberName = (Get-ADUser $Member).name
        }

        if ($GroupMembers -contains $MemberName) {
            Write-Host "$MemberName - existed" -ForegroundColor Yellow
            $record = "$Time | $GroupName | $Member - Duplicated"
            # $filtered += $MemberName
        } else {
            Write-Host $MemberName            
            # $filtered += $MemberName
            $record = "$Time | $GroupName | $Member"
        }

        $filtered += $MemberName
        # Add-Content $LogFile $record
    } catch {
        write-Host "$Member - not found" -ForegroundColor Red
        $record = "$Time | $GroupName | $Member - not found"
    }
    Add-Content $LogFile $record
}


Write-Host "$Operation $CollectionType in the $GroupName" -foreground magenta
if ($filtered.count -gt 0) {
    $filtered | % {
        foreach ($dc in $DCs) {
            if ($Operation -ieq "Adding") {
                if ($CollectionType -ieq "Computer") {
                    Add-ADGroupMember -Identity $GroupName -members (Get-ADComputer $_) -Server $dc
                } else {
                    Add-ADGroupMember -Identity $GroupName -Members $_ -Server $dc
                }
            } else {
                if ($CollectionType -ieq "Computer") {
                    Remove-ADGroupMember -Identity $GroupName -members (Get-ADComputer $_) -Server $dc -Confirm:$false
                } else {
                    Remove-ADGroupMember -Identity $GroupName -Members $_ -Server $dc -Confirm:$false
                }
            }
        }
    }
}

# Remove-ADGroupMember -Identity "APP MS Office 2016 x86 ProPlus - Day 1" -Members (Get-ADComputer R902EK4H)

# $filtered ="5CG63101G0"

$GroupMembers = (Get-ADGroupMember -Identity $GroupName).name;$filtered | %{ if ($GroupMembers -contains $_) {Write-Host "$_ is in AD Group - $GroupName" -ForegroundColor Green} else {Write-Host "$_ is not in the AD Group - $GroupName" -ForegroundColor Red} }

Write-Host "Pause for 1 min" -ForegroundColor Magenta
Start-Sleep -Seconds 60

Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"
Set-Location $SiteCode":\"

Write-Host "Updating Collection - $CollectionName" -Foreground Magenta
Update-CMCollection -CollectionName $CollectionName -CollectionType $CollectionType -SiteCode $SiteCode -SiteServer $SiteServer -Wait -Verbose

$SMSMemebers = Get-SMSMembers -SiteServer $SiteServer -SiteCode $SiteCode -CollectionName $CollectionName;$filtered | %{ if ($SMSMemebers -contains $_) {Write-Host "$_ is in the Collection - $CollectionName" -ForegroundColor Green} else {Write-Host "$_ is not in the Collection - $CollectionName" -ForegroundColor Red} }
