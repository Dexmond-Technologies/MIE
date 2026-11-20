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
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $enc1 = "-encodedcommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $enc3 = "/enc " ascii wide nocase
        $hidden1 = "-windowstyle hidden" ascii wide nocase
        $hidden2 = "-w hidden" ascii wide nocase
        $bypass1 = "-executionpolicy bypass" ascii wide nocase
        $bypass2 = "-ep bypass" ascii wide nocase
    condition:
        any of ($ps*) and any of ($enc*, $hidden*, $bypass*)
}

rule Ransomware_Note_Indicators
{
    meta:
        description = "Strings typical of ransomware ransom notes"
        severity = "high"
        author = "DEXMOND MIE"
    strings:
        $r1 = "your files have been encrypted" ascii wide nocase
        $r2 = "decrypt your files" ascii wide nocase
        $r3 = "bitcoin" ascii wide nocase
        $r4 = "pay the ransom" ascii wide nocase
        $r5 = "restore your files" ascii wide nocase
    condition:
        filesize < 64KB and uint16(0) != 0x5A4D and ($r1 or $r2 or $r4) and 2 of them
}

rule AntiDebug_AntiVM_Strings
{
    meta:
        description = "Anti-debugging / anti-VM technique indicators"
        severity = "medium"
        category = "imports"
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
