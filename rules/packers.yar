rule Packer_UPX
{
    meta:
        description = "UPX packed executable"
        severity = "medium"
        category = "packer"
        author = "DEXMOND MIE"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_sig = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Packer_Themida_VMProtect
{
    meta:
        description = "Themida/VMProtect protected executable"
        severity = "medium"
        category = "packer"
        author = "DEXMOND MIE"
    strings:
        $vmp0 = ".vmp0" ascii
        $vmp1 = ".vmp1" ascii
        $themida = ".themida" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
