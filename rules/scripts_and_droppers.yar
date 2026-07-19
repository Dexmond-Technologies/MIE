rule JS_Obfuscated_Dropper
{
    meta:
        description = "Obfuscated JavaScript dropper patterns"
        severity = "high"
        author = "DEXMOND MIE"
    strings:
        $a = "eval(" ascii
        $b = "unescape(" ascii
        $c = "fromCharCode" ascii
        $d = "ActiveXObject" ascii
        $e = "WScript.Shell" ascii
    condition:
        3 of them
}

rule VBS_Macro_Downloader
{
    meta:
        description = "VBScript / macro downloader indicators"
        severity = "high"
        author = "DEXMOND MIE"
    strings:
        $a = "CreateObject" ascii nocase
        $b = "MSXML2.XMLHTTP" ascii nocase
        $c = "ADODB.Stream" ascii nocase
        $d = "Shell.Application" ascii nocase
        $e = "WinHttp.WinHttpRequest" ascii nocase
    condition:
        2 of them
}

rule Office_Macro_AutoExec
{
    meta:
        description = "Office macro auto-execution entry points"
        severity = "medium"
        author = "DEXMOND MIE"
    strings:
        $a = "AutoOpen" ascii
        $b = "Document_Open" ascii
        $c = "Workbook_Open" ascii
        $d = "Auto_Close" ascii
        $e = "Shell(" ascii
    condition:
        2 of them
}

rule Suspicious_Batch_Commands
{
    meta:
        description = "Batch/CMD abuse indicators"
        severity = "medium"
        author = "DEXMOND MIE"
    strings:
        $a = "vssadmin delete shadows" ascii nocase
        $b = "bcdedit /set" ascii nocase
        $c = "wbadmin delete catalog" ascii nocase
        $d = "netsh firewall" ascii nocase
        $e = "reg add" ascii nocase
        $f = "schtasks /create" ascii nocase
    condition:
        2 of them
}
