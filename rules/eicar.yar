rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus standard test file"
        severity = "critical"
        author = "DEXMOND MIE"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar
}
