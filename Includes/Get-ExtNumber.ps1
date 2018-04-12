function Get-ExtNumber {
    # param([string]$Identity)
    # $DisplayName = (Get-ADUser ($env:USERNAME) -Properties DisplayName).DisplayName
    $UserName = $env:USERNAME
    <#
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
    #>
    $ExtTable = @{
        "AMRANIH"      = "7843050";
        "CHAHALN"      = "7843022";
        "choih"          = "7843023";
        "HOSSENZ"       = "7843041";
        "MACLEODJ"    = "7843024";
        "MAMUNM" = "7843026";
        "PURIL"          = "7843017";
        "Saadm"      = "7843057";
        "ZAHEERM"      = "7843034";
        "ZHANGB"           = "7843031";
	"SEEDSMAC" = "7843107";
	"STEWARTT" = "7843037"
    }
    
    return $ExtTable[$UserName].Substring(3,4)
}