rule win_yakuza_ransomware_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.yakuza_ransomware."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yakuza_ransomware"
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
        $sequence_0 = { 8bd1 d1ea b8ffffff1f 2bc2 3bc8 7607 8bc3 }
            // n = 7, score = 100
            //   8bd1                 | mov                 edx, ecx
            //   d1ea                 | shr                 edx, 1
            //   b8ffffff1f           | mov                 eax, 0x1fffffff
            //   2bc2                 | sub                 eax, edx
            //   3bc8                 | cmp                 ecx, eax
            //   7607                 | jbe                 9
            //   8bc3                 | mov                 eax, ebx

        $sequence_1 = { e8???????? 3b780c 730e 8b4008 8b34b8 85f6 0f85d7000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   3b780c               | cmp                 edi, dword ptr [eax + 0xc]
            //   730e                 | jae                 0x10
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   8b34b8               | mov                 esi, dword ptr [eax + edi*4]
            //   85f6                 | test                esi, esi
            //   0f85d7000000         | jne                 0xdd

        $sequence_2 = { d1f8 837e1408 7202 8b36 50 ff7508 8bce }
            // n = 7, score = 100
            //   d1f8                 | sar                 eax, 1
            //   837e1408             | cmp                 dword ptr [esi + 0x14], 8
            //   7202                 | jb                  4
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8bce                 | mov                 ecx, esi

        $sequence_3 = { 6a01 6a01 57 8d4d80 e8???????? 8b4580 8d4d80 }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   6a01                 | push                1
            //   57                   | push                edi
            //   8d4d80               | lea                 ecx, [ebp - 0x80]
            //   e8????????           |                     
            //   8b4580               | mov                 eax, dword ptr [ebp - 0x80]
            //   8d4d80               | lea                 ecx, [ebp - 0x80]

        $sequence_4 = { 8d7018 83c030 8b11 03c7 50 03f7 56 }
            // n = 7, score = 100
            //   8d7018               | lea                 esi, [eax + 0x18]
            //   83c030               | add                 eax, 0x30
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax
            //   03f7                 | add                 esi, edi
            //   56                   | push                esi

        $sequence_5 = { c745fcffffffff 56 8b4de0 41 51 53 8bcf }
            // n = 7, score = 100
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   56                   | push                esi
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   41                   | inc                 ecx
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   8bcf                 | mov                 ecx, edi

        $sequence_6 = { 8b4f14 8b5614 85c9 743e 85c0 750d e8???????? }
            // n = 7, score = 100
            //   8b4f14               | mov                 ecx, dword ptr [edi + 0x14]
            //   8b5614               | mov                 edx, dword ptr [esi + 0x14]
            //   85c9                 | test                ecx, ecx
            //   743e                 | je                  0x40
            //   85c0                 | test                eax, eax
            //   750d                 | jne                 0xf
            //   e8????????           |                     

        $sequence_7 = { eb17 0fb74644 8d4e24 50 e8???????? 6a2d 8d4e24 }
            // n = 7, score = 100
            //   eb17                 | jmp                 0x19
            //   0fb74644             | movzx               eax, word ptr [esi + 0x44]
            //   8d4e24               | lea                 ecx, [esi + 0x24]
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a2d                 | push                0x2d
            //   8d4e24               | lea                 ecx, [esi + 0x24]

        $sequence_8 = { 8b06 6a02 51 53 8d8d50ffffff 51 8bce }
            // n = 7, score = 100
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   6a02                 | push                2
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   8d8d50ffffff         | lea                 ecx, [ebp - 0xb0]
            //   51                   | push                ecx
            //   8bce                 | mov                 ecx, esi

        $sequence_9 = { c745f000000000 c7461000000000 c7461407000000 668906 8945fc 8bc3 c745f001000000 }
            // n = 7, score = 100
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   c7461407000000       | mov                 dword ptr [esi + 0x14], 7
            //   668906               | mov                 word ptr [esi], ax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8bc3                 | mov                 eax, ebx
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1

    condition:
        7 of them and filesize < 2811904
}