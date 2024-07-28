rule win_luminosity_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.luminosity_rat"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { d932 17 89b9089bb191 44 dcf3 bd5774bc09 87f7 }
            // n = 7, score = 100
            //   d932                 | fnstenv             [edx]
            //   17                   | pop                 ss
            //   89b9089bb191         | mov                 dword ptr [ecx - 0x6e4e64f8], edi
            //   44                   | inc                 esp
            //   dcf3                 | fdivr               st(3), st(0)
            //   bd5774bc09           | mov                 ebp, 0x9bc7457
            //   87f7                 | xchg                edi, esi

        $sequence_1 = { 63b1343b3802 f7c57d03a193 f8 ce d932 17 89b9089bb191 }
            // n = 7, score = 100
            //   63b1343b3802         | arpl                word ptr [ecx + 0x2383b34], si
            //   f7c57d03a193         | test                ebp, 0x93a1037d
            //   f8                   | clc                 
            //   ce                   | into                
            //   d932                 | fnstenv             [edx]
            //   17                   | pop                 ss
            //   89b9089bb191         | mov                 dword ptr [ecx - 0x6e4e64f8], edi

        $sequence_2 = { 6a66 d6 1d38f117aa e6fe a1???????? 40 633f }
            // n = 7, score = 100
            //   6a66                 | push                0x66
            //   d6                   | salc                
            //   1d38f117aa           | sbb                 eax, 0xaa17f138
            //   e6fe                 | out                 0xfe, al
            //   a1????????           |                     
            //   40                   | inc                 eax
            //   633f                 | arpl                word ptr [edi], di

        $sequence_3 = { 7d8d 82d976 3c1b d473 }
            // n = 4, score = 100
            //   7d8d                 | jge                 0xffffff8f
            //   82d976               | sbb                 cl, 0x76
            //   3c1b                 | cmp                 al, 0x1b
            //   d473                 | aam                 0x73

        $sequence_4 = { 58 07 a82c 5b }
            // n = 4, score = 100
            //   58                   | pop                 eax
            //   07                   | pop                 es
            //   a82c                 | test                al, 0x2c
            //   5b                   | pop                 ebx

        $sequence_5 = { 731c 137c62f6 333e 56 9c }
            // n = 5, score = 100
            //   731c                 | jae                 0x1e
            //   137c62f6             | adc                 edi, dword ptr [edx - 0xa]
            //   333e                 | xor                 edi, dword ptr [esi]
            //   56                   | push                esi
            //   9c                   | pushfd              

        $sequence_6 = { 63b1343b3802 f7c57d03a193 f8 ce d932 17 }
            // n = 6, score = 100
            //   63b1343b3802         | arpl                word ptr [ecx + 0x2383b34], si
            //   f7c57d03a193         | test                ebp, 0x93a1037d
            //   f8                   | clc                 
            //   ce                   | into                
            //   d932                 | fnstenv             [edx]
            //   17                   | pop                 ss

        $sequence_7 = { 40 633f 7fd4 f9 d398c9bd0fcc 54 }
            // n = 6, score = 100
            //   40                   | inc                 eax
            //   633f                 | arpl                word ptr [edi], di
            //   7fd4                 | jg                  0xffffffd6
            //   f9                   | stc                 
            //   d398c9bd0fcc         | rcr                 dword ptr [eax - 0x33f04237], cl
            //   54                   | push                esp

        $sequence_8 = { 22f2 f8 f5 e52d 33f6 4c }
            // n = 6, score = 100
            //   22f2                 | and                 dh, dl
            //   f8                   | clc                 
            //   f5                   | cmc                 
            //   e52d                 | in                  eax, 0x2d
            //   33f6                 | xor                 esi, esi
            //   4c                   | dec                 esp

        $sequence_9 = { 4b f38b80c19a082c 7d00 d0d7 8909 8aaac7737e7b 815adf62076722 }
            // n = 7, score = 100
            //   4b                   | dec                 ebx
            //   f38b80c19a082c       | mov                 eax, dword ptr [eax + 0x2c089ac1]
            //   7d00                 | jge                 2
            //   d0d7                 | rcl                 bh, 1
            //   8909                 | mov                 dword ptr [ecx], ecx
            //   8aaac7737e7b         | mov                 ch, byte ptr [edx + 0x7b7e73c7]
            //   815adf62076722       | sbb                 dword ptr [edx - 0x21], 0x22670762

    condition:
        7 of them and filesize < 811008
}