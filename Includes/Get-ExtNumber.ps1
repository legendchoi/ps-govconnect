function Get-ExtNumber {
    # param([string]$Identity)

    # $Identity = $env:USERNAME
    # $DisplayName = (Get-ADUser $Identity -Properties DisplayName).DisplayName
    $DisplayName = (Get-ADUser ($env:USERNAME) -Properties DisplayName).DisplayName
    # $DisplayName
    $ExtTable = @{
        "Hacene Amrani"      = "7843050";
        "Naphez Chahal"      = "7843022";
        "Hyun Choi"          = "7843023";
        "Zakir Hossen"       = "7843041";
        "Jasmine Macleod"    = "7843024";
        "Md Muntashir Mamun" = "7843026";
        "Liza Puri"          = "7843017";
        "Saad Muhammad"      = "7843057";
        "Chris Sarulidis"    = "7843028";
        "Mohsin Zaheer"      = "7843034";
        "Bo Zhang"           = "7843031"
    }
    # $ExtTable[$DisplayName]
    return $ExtTable[$DisplayName].Substring(3,4)
}