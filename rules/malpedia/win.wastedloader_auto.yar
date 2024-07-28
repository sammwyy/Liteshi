rule win_wastedloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.wastedloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wastedloader"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { b748 00ee 0be6 3bf6 2014dd33b89819 220f }
            // n = 6, score = 100
            //   b748                 | mov                 bh, 0x48
            //   00ee                 | add                 dh, ch
            //   0be6                 | or                  esp, esi
            //   3bf6                 | cmp                 esi, esi
            //   2014dd33b89819       | and                 byte ptr [ebx*8 + 0x1998b833], dl
            //   220f                 | and                 cl, byte ptr [edi]

        $sequence_1 = { 0fb7485e 83e954 8b55f8 66894a5e }
            // n = 4, score = 100
            //   0fb7485e             | movzx               ecx, word ptr [eax + 0x5e]
            //   83e954               | sub                 ecx, 0x54
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   66894a5e             | mov                 word ptr [edx + 0x5e], cx

        $sequence_2 = { fc b802ec0000 8d6825 94 01dc 00e8 45 }
            // n = 7, score = 100
            //   fc                   | cld                 
            //   b802ec0000           | mov                 eax, 0xec02
            //   8d6825               | lea                 ebp, [eax + 0x25]
            //   94                   | xchg                eax, esp
            //   01dc                 | add                 esp, ebx
            //   00e8                 | add                 al, ch
            //   45                   | inc                 ebp

        $sequence_3 = { b802ec0000 8d6825 94 01dc 00e8 45 }
            // n = 6, score = 100
            //   b802ec0000           | mov                 eax, 0xec02
            //   8d6825               | lea                 ebp, [eax + 0x25]
            //   94                   | xchg                eax, esp
            //   01dc                 | add                 esp, ebx
            //   00e8                 | add                 al, ch
            //   45                   | inc                 ebp

        $sequence_4 = { ec 7ac4 f8 ae fc }
            // n = 5, score = 100
            //   ec                   | in                  al, dx
            //   7ac4                 | jp                  0xffffffc6
            //   f8                   | clc                 
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   fc                   | cld                 

        $sequence_5 = { 32705b 39e1 108792ff9b95 8abf2ec8650b }
            // n = 4, score = 100
            //   32705b               | xor                 dh, byte ptr [eax + 0x5b]
            //   39e1                 | cmp                 ecx, esp
            //   108792ff9b95         | adc                 byte ptr [edi - 0x6a64006e], al
            //   8abf2ec8650b         | mov                 bh, byte ptr [edi + 0xb65c82e]

        $sequence_6 = { 1a00 0071bf 7303 1f c8be8de8 1be8 692405008008202c00700d }
            // n = 7, score = 100
            //   1a00                 | sbb                 al, byte ptr [eax]
            //   0071bf               | add                 byte ptr [ecx - 0x41], dh
            //   7303                 | jae                 5
            //   1f                   | pop                 ds
            //   c8be8de8             | enter               -0x7242, -0x18
            //   1be8                 | sbb                 ebp, eax
            //   692405008008202c00700d     | imul    esp, dword ptr [eax + 0x20088000], 0xd70002c

        $sequence_7 = { 66894118 8b55f8 0fb74218 83e854 8b4df8 66894118 ba8d000000 }
            // n = 7, score = 100
            //   66894118             | mov                 word ptr [ecx + 0x18], ax
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   0fb74218             | movzx               eax, word ptr [edx + 0x18]
            //   83e854               | sub                 eax, 0x54
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   66894118             | mov                 word ptr [ecx + 0x18], ax
            //   ba8d000000           | mov                 edx, 0x8d

        $sequence_8 = { 2cbe 832061 5b 5b }
            // n = 4, score = 100
            //   2cbe                 | sub                 al, 0xbe
            //   832061               | and                 dword ptr [eax], 0x61
            //   5b                   | pop                 ebx
            //   5b                   | pop                 ebx

        $sequence_9 = { 30ac06e68bfc49 23f7 b754 7c49 27 59 }
            // n = 6, score = 100
            //   30ac06e68bfc49       | xor                 byte ptr [esi + eax + 0x49fc8be6], ch
            //   23f7                 | and                 esi, edi
            //   b754                 | mov                 bh, 0x54
            //   7c49                 | jl                  0x4b
            //   27                   | daa                 
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 2677760
}