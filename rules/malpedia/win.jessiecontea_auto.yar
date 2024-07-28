rule win_jessiecontea_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.jessiecontea."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jessiecontea"
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
        $sequence_0 = { c78590f4ffff00000000 c7858cf4ffff00000000 c78588f4ffff00000000 c78594f4ffff01000000 c78598f4ffff01000000 e8???????? }
            // n = 6, score = 300
            //   c78590f4ffff00000000     | mov    dword ptr [ebp - 0xb70], 0
            //   c7858cf4ffff00000000     | mov    dword ptr [ebp - 0xb74], 0
            //   c78588f4ffff00000000     | mov    dword ptr [ebp - 0xb78], 0
            //   c78594f4ffff01000000     | mov    dword ptr [ebp - 0xb6c], 1
            //   c78598f4ffff01000000     | mov    dword ptr [ebp - 0xb68], 1
            //   e8????????           |                     

        $sequence_1 = { 3d00010000 0f8f03010000 6a00 6a00 50 }
            // n = 5, score = 300
            //   3d00010000           | cmp                 eax, 0x100
            //   0f8f03010000         | jg                  0x109
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_2 = { 8d85e8fdffff 50 8d85a2f6ffff 50 }
            // n = 4, score = 300
            //   8d85e8fdffff         | lea                 eax, [ebp - 0x218]
            //   50                   | push                eax
            //   8d85a2f6ffff         | lea                 eax, [ebp - 0x95e]
            //   50                   | push                eax

        $sequence_3 = { 57 8b7d18 8945c0 8b4510 }
            // n = 4, score = 300
            //   57                   | push                edi
            //   8b7d18               | mov                 edi, dword ptr [ebp + 0x18]
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_4 = { eb02 2bf7 6a00 8d85e8b7ffff 50 }
            // n = 5, score = 300
            //   eb02                 | jmp                 4
            //   2bf7                 | sub                 esi, edi
            //   6a00                 | push                0
            //   8d85e8b7ffff         | lea                 eax, [ebp - 0x4818]
            //   50                   | push                eax

        $sequence_5 = { 5d c3 c705????????31090000 5f 5e 5b 8be5 }
            // n = 7, score = 300
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   c705????????31090000     |     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_6 = { 56 57 680a020000 8d85d8fbffff 8bf2 6a00 }
            // n = 6, score = 300
            //   56                   | push                esi
            //   57                   | push                edi
            //   680a020000           | push                0x20a
            //   8d85d8fbffff         | lea                 eax, [ebp - 0x428]
            //   8bf2                 | mov                 esi, edx
            //   6a00                 | push                0

        $sequence_7 = { 6880000000 6a01 6a00 6a01 6800000040 8d85f8fbffff 50 }
            // n = 7, score = 300
            //   6880000000           | push                0x80
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6800000040           | push                0x40000000
            //   8d85f8fbffff         | lea                 eax, [ebp - 0x408]
            //   50                   | push                eax

        $sequence_8 = { 41b800080000 be20000008 e8???????? 33d2 448975c0 }
            // n = 5, score = 100
            //   41b800080000         | dec                 eax
            //   be20000008           | xor                 eax, edx
            //   e8????????           |                     
            //   33d2                 | test                eax, eax
            //   448975c0             | jne                 0xfffffc88

        $sequence_9 = { 4d8bc8 4d2bcd 6690 488d82fafeff7f }
            // n = 4, score = 100
            //   4d8bc8               | dec                 eax
            //   4d2bcd               | mov                 ecx, dword ptr [esp + 0x60]
            //   6690                 | inc                 ecx
            //   488d82fafeff7f       | mov                 eax, 0x800

        $sequence_10 = { 83e03f 2bc8 33c0 48d3c8 488d0d39d20100 4833c2 }
            // n = 6, score = 100
            //   83e03f               | cmp                 dword ptr [ebp + 0x50], edi
            //   2bc8                 | jb                  0x32
            //   33c0                 | and                 eax, 0x3f
            //   48d3c8               | sub                 ecx, eax
            //   488d0d39d20100       | xor                 eax, eax
            //   4833c2               | dec                 eax

        $sequence_11 = { 7305 44887c3710 488bcb e8???????? 397d50 7230 }
            // n = 6, score = 100
            //   7305                 | jae                 7
            //   44887c3710           | inc                 esp
            //   488bcb               | mov                 byte ptr [edi + esi + 0x10], bh
            //   e8????????           |                     
            //   397d50               | dec                 eax
            //   7230                 | mov                 ecx, ebx

        $sequence_12 = { ff15???????? 85c0 0f8580fcffff 488b4c2460 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   85c0                 | ror                 eax, cl
            //   0f8580fcffff         | dec                 eax
            //   488b4c2460           | lea                 ecx, [0x1d239]

        $sequence_13 = { 892d???????? 8b1d???????? 488d4c2430 8bfd 48896c2430 }
            // n = 5, score = 100
            //   892d????????         |                     
            //   8b1d????????         |                     
            //   488d4c2430           | dec                 eax
            //   8bfd                 | lea                 eax, [edx + 0x7ffffefa]
            //   48896c2430           | dec                 eax

        $sequence_14 = { 4889442440 33d2 4489742448 41b8ff3f0000 488d8d51070000 }
            // n = 5, score = 100
            //   4889442440           | dec                 ebp
            //   33d2                 | mov                 ecx, eax
            //   4489742448           | dec                 ebp
            //   41b8ff3f0000         | sub                 ecx, ebp
            //   488d8d51070000       | nop                 

        $sequence_15 = { 488b4d98 488d4588 4889442428 41b902000000 }
            // n = 4, score = 100
            //   488b4d98             | mov                 esi, 0x8000020
            //   488d4588             | xor                 edx, edx
            //   4889442428           | inc                 esp
            //   41b902000000         | mov                 dword ptr [ebp - 0x40], esi

    condition:
        7 of them and filesize < 413696
}