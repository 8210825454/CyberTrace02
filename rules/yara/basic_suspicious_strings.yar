rule CyberTrace_Suspicious_Script_Strings {
    meta:
        description = "Training rule for selected suspicious script strings"
        author = "CyberTrace"
    strings:
        $a = "Invoke-Expression" nocase
        $b = "DownloadString" nocase
        $c = "FromBase64String" nocase
    condition:
        any of them
}