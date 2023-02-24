rule Microsoft_OneNote_with_Suspicious_String
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects an Microsoft OneNote files containing suspicious strings."
        created_date   = "2023-02-24"
        updated_date   = "2023-02-24"
        blog_reference = "N/A"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "73dc35d1fa8d1e3147a5fe6056e01f89847441ec46175ba60b24a56b7fbdf2f9"

    strings:
        $suspicious_00 = "<script" nocase ascii wide
        $suspicious_01 = "cmd.exe" nocase ascii wide
        $suspicious_02 = "CreateObject" nocase ascii wide
        $suspicious_03 = "CreateProcess" nocase ascii wide
        $suspicious_04 = "echo off" nocase ascii wide
        $suspicious_05 = "ExecuteCmdAsync" nocase ascii wide
        $suspicious_06 = "mshta" nocase ascii wide
        $suspicious_07 = "msiexec" nocase ascii wide
        $suspicious_08 = "powershell" nocase ascii wide
        $suspicious_09 = "regsvr32" nocase ascii wide
        $suspicious_10 = "rundll32" nocase ascii wide
        $suspicious_11 = "schtasks" nocase ascii wide
        $suspicious_12 = "SetEnvironmentVariable" nocase ascii wide
        $suspicious_13 = "winmgmts" nocase ascii wide
        $suspicious_14 = "Wscript" nocase ascii wide
        $suspicious_15 = "WshShell" nocase ascii wide
    condition:
        uint32be(0) == 0xE4525C7B and any of ($suspicious*)
}
