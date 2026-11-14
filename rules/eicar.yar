rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus standard test file"
        severity = "critical"
        author = "DEXMOND MIE"
        reference = "EICAR spec: 68-byte string at the start of the file, optionally followed by whitespace, total at most 128 bytes"
    strings:
        // split in two so this rule file never holds the test string in one piece
        $head = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" ascii
        $body = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $head at 0 and $body at 28 and filesize <= 128
}
