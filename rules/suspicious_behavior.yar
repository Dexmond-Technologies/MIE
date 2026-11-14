rule Process_Injection_APIs
{
    meta:
        description = "Combination of APIs commonly used for process injection"
        severity = "high"
        category = "imports"
        author = "DEXMOND MIE"
    strings:
        $a1 = "VirtualAllocEx" ascii
        $a2 = "WriteProcessMemory" ascii
        $a3 = "CreateRemoteThread" ascii
        $a4 = "NtCreateThreadEx" ascii
        $a5 = "QueueUserAPC" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell with encoded/hidden command indicators"
        severity = "high"
        author = "DEXMOND MIE"
    strings:
        $ps = "powershell" ascii nocase
        $enc1 = "-encodedcommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $hidden = "-windowstyle hidden" ascii nocase
        $bypass = "-executionpolicy bypass" ascii nocase
    condition:
        $ps and any of ($enc1, $enc2, $hidden, $bypass)
}

rule Ransomware_Note_Indicators
{
    meta:
        description = "Strings typical of ransomware ransom notes"
        severity = "critical"
        author = "DEXMOND MIE"
    strings:
        $r1 = "your files have been encrypted" ascii nocase
        $r2 = "decrypt your files" ascii nocase
        $r3 = "bitcoin" ascii nocase
        $r4 = "pay the ransom" ascii nocase
        $r5 = "restore your files" ascii nocase
    condition:
        2 of them
}

rule AntiDebug_AntiVM_Strings
{
    meta:
        description = "Anti-debugging / anti-VM technique indicators"
        severity = "medium"
        author = "DEXMOND MIE"
    strings:
        $d1 = "IsDebuggerPresent" ascii
        $d2 = "CheckRemoteDebuggerPresent" ascii
        $v1 = "VBoxService" ascii nocase
        $v2 = "vmtoolsd" ascii nocase
        $v3 = "SbieDll.dll" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
