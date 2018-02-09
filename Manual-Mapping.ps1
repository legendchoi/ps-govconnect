. "$PSScriptRoot\includes\functions.ps1"

function Get-CMPrimaryDevice {
    param($Identity)

    $CurrentLocation = Get-Location
    # Import the ConfigurationManager.psd1 module 
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"
    # Set the current location to be the site code.

    Set-Location "P01:"
    $computers = (Get-CMUserDeviceAffinity -UserName "govnet\$identity").ResourceName
    Write-Host $CurrentLocation
    Set-Location $CurrentLocation

    return $computers
}

function Get-GPOResultReport {
    param (
        $ComputerName,
        $UserName,
        $ReportFilePath,
        $ReportFileName
    )
    $ReportFilePath = "H:\Temp"
    $ReportFileName = "GPOResult-$ComputerName-$UserName.html"
    Get-gpresultantsetofpolicy -Computer $ComputerName -ReportType Html -Path "$ReportFilePath\$ReportFileName" -User $UserName
    # Show the Report in IE 
    $ie = New-Object -ComObject InternetExplorer.Application
    $ie.Navigate("$ReportFilePath\$ReportFileName")
    $ie.Visible = $true
}

function Get-RegMappedDrive {
    param (
        [Parameter(Mandatory=$true)]$ComputerName, 
        [Parameter(Mandatory=$true)]$UserName    
    )

    $SID=(Get-ADUser $UserName).SID.Value

    $keypath = "$sid\Network"
    # $hkeytype = [Microsoft.Win32.RegistryHive]::Users
    # $basekey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hkeytype,$ComputerName)

    # $computername
    # $username
    # $sid
    # $keypath

    if (Test-Connection -ComputerName $ComputerName -count 1 -ea 0) {
        $hkeytype = [Microsoft.Win32.RegistryHive]::Users
        $basekey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hkeytype,$ComputerName)

        try {
            $subkey = $basekey.OpenSubKey($keypath,$true)
            $subkeynames = $subkey.GetSubKeyNames()
            foreach ($subkeyname in $subkeynames) {
                Write-Host "Drive $subkeyname : " -NoNewline
                $newkeypath = $keypath+"\$subkeyname"
                $newsubkey = $basekey.OpenSubKey($newkeypath,$true)
                $newsubkey.GetValue("RemotePath")
            }

        } catch {
            Write-Host "Currently $UserName is not logged on $ComputerName" -ForegroundColor Red
        }

    } else {
        Write-Host "$ComputerName is not responding. Possibly it is not online" -ForegroundColor Red
    } 
}

function Set-RegMapDrive {
    param (
        [Parameter(Mandatory=$true)]$ComputerName,
        [Parameter(Mandatory=$true)]$UserName,
        [Parameter(Mandatory=$true)]$DriveLetter,
        [Parameter(Mandatory=$true)]$DrivePath
    )

    $SID=(Get-ADUser $UserName).SID.Value

    $keypath = "$sid\Network"
    $hkeytype = [Microsoft.Win32.RegistryHive]::Users
    $basekey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hkeytype,$ComputerName)

    if (Test-Connection -ComputerName $ComputerName -count 1 -ea 0) {
        
        try {

            $subkey = $basekey.OpenSubKey($keypath,$true)
            $subkey.CreateSubKey($DriveLetter)

            $newkeypath = $keypath+"\$DriveLetter"
            $newsubkey = $basekey.OpenSubKey($newkeypath,$true)

            $newSubKey.SetValue("RemotePath", $DrivePath, [Microsoft.Win32.RegistryValueKind]::String)
            $newSubKey.SetValue("UserName", 0, [Microsoft.Win32.RegistryValueKind]::DWORD)
            $newSubKey.SetValue("ProviderName", "Microsoft Windows Network", [Microsoft.Win32.RegistryValueKind]::String)
            $newSubKey.SetValue("ProviderType", 131072, [Microsoft.Win32.RegistryValueKind]::DWORD)
            $newSubKey.SetValue("ConnectionType", 1, [Microsoft.Win32.RegistryValueKind]::DWORD)
            $newSubKey.SetValue("ProviderFlags", 1, [Microsoft.Win32.RegistryValueKind]::DWORD)
            $newSubKey.SetValue("DeferFlags", 4, [Microsoft.Win32.RegistryValueKind]::DWORD)

        } catch {

            Write-Host "Currently $UserName is not logged on $ComputerName" -ForegroundColor Red
        }

    } else {
        Write-Host "$computer is not responding. Possibly it is not online" -ForegroundColor Red
    }

}


# Main 
# Select User
Clear-Host

$identity = Select-User
$sid=(Get-ADUser $identity).SID.Value


$Computers = Get-CMPrimaryDevice -Identity $identity

# Select the computer in interest
# Set-Location "H:" 
if ($computers) {
    if ($computers.Count -gt 1) {
        $Number = 1
        $ComList=@()
        foreach ($Computer in $Computers) {
            $ComList += New-Object -TypeName psobject -Property @{'Number'=$Number;'Computer'=$computer}
            $Number++
        }
        $ComList | ft Number, Computer -AutoSize
        $ComNo = Read-Host "Which one?"
        $Computer = $computers[$ComNo-1]
    } else {
        $Computer = $computers
    }

    # Write-Host "Computer selected $computer" -ForegroundColor Green
} else {
    Write-Host "No computer(s) associated found" -ForegroundColor Red
    $computer = Read-Host "Please provide the computer name"
}

# ---------------------------
# Unit Test
# $identity = "SCHAAPP"
# $computer = "R90N48XJ"
# ---------------------------

Write-Host "Computer selected $computer" -ForegroundColor Green

# Check network connectivity
if (Test-Connection -ComputerName $Computer -count 1 -ea 0) {

    Write-Host "List of existing Drives"
    Get-RegMappedDrive -ComputerName $Computer -UserName $identity

    $Choice = Read-Host "Wanna map a new net drive? (y/n)"

    if ($Choice -ieq 'y') {
        $Letter = Read-Host "New Drive Letter"
        $Path = Read-Host "Provide Drive Path"
        Set-RegMapDrive -ComputerName $Computer -UserName $identity -DriveLetter $Letter -DrivePath $Path
        Get-RegMappedDrive -ComputerName $Computer -UserName $identity
    }

} else {
    Write-Host "Ping ... $computer is not responding. Possibly it is not online" -ForegroundColor Red
}

# Show GPO Report in IE
# Write-Host "GPO Report for Map Drive Policy"
# Get-GPOResultReport -ComputerName $Computer -UserName $identity

Write-Host "Bye"