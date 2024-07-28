rule win_scarabey_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.scarabey."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scarabey"
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
        $sequence_0 = { 8bf0 85f6 7478 8b8dfcd6ffff 8b95f4d6ffff 8d85fcd6ffff 50 }
            // n = 7, score = 100
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7478                 | je                  0x7a
            //   8b8dfcd6ffff         | mov                 ecx, dword ptr [ebp - 0x2904]
            //   8b95f4d6ffff         | mov                 edx, dword ptr [ebp - 0x290c]
            //   8d85fcd6ffff         | lea                 eax, [ebp - 0x2904]
            //   50                   | push                eax

        $sequence_1 = { e8???????? c745fcffffffff 8b06 8b7e04 2bf8 85c0 7409 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b7e04               | mov                 edi, dword ptr [esi + 4]
            //   2bf8                 | sub                 edi, eax
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb

        $sequence_2 = { 51 52 ffd3 6a40 6800300000 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ffd3                 | call                ebx
            //   6a40                 | push                0x40
            //   6800300000           | push                0x3000

        $sequence_3 = { ff15???????? 56 ff15???????? a1???????? 33f6 56 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   a1????????           |                     
            //   33f6                 | xor                 esi, esi
            //   56                   | push                esi

        $sequence_4 = { ba12000000 8d0dd0ad5700 e9???????? db2d???????? d9c9 d9f5 9b }
            // n = 7, score = 100
            //   ba12000000           | mov                 edx, 0x12
            //   8d0dd0ad5700         | lea                 ecx, [0x57add0]
            //   e9????????           |                     
            //   db2d????????         |                     
            //   d9c9                 | fxch                st(1)
            //   d9f5                 | fprem1              
            //   9b                   | wait                

        $sequence_5 = { 7d04 8944241c 686666aa00 50 33db 6a02 895c2450 }
            // n = 7, score = 100
            //   7d04                 | jge                 6
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   686666aa00           | push                0xaa6666
            //   50                   | push                eax
            //   33db                 | xor                 ebx, ebx
            //   6a02                 | push                2
            //   895c2450             | mov                 dword ptr [esp + 0x50], ebx

        $sequence_6 = { 8bc8 8b8524d7ffff 83c005 8d14c500000000 2bd0 a1???????? 03ca }
            // n = 7, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   8b8524d7ffff         | mov                 eax, dword ptr [ebp - 0x28dc]
            //   83c005               | add                 eax, 5
            //   8d14c500000000       | lea                 edx, [eax*8]
            //   2bd0                 | sub                 edx, eax
            //   a1????????           |                     
            //   03ca                 | add                 ecx, edx

        $sequence_7 = { e8???????? 8b4d08 8b83d40c0000 8bf0 83f907 7771 ff248d690c4700 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b83d40c0000         | mov                 eax, dword ptr [ebx + 0xcd4]
            //   8bf0                 | mov                 esi, eax
            //   83f907               | cmp                 ecx, 7
            //   7771                 | ja                  0x73
            //   ff248d690c4700       | jmp                 dword ptr [ecx*4 + 0x470c69]

        $sequence_8 = { eb4c 8d4c2404 68???????? 51 e8???????? 83c408 84c0 }
            // n = 7, score = 100
            //   eb4c                 | jmp                 0x4e
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   68????????           |                     
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   84c0                 | test                al, al

        $sequence_9 = { c744240808000000 c744240cff000000 ff15???????? 8bce e8???????? 6a00 e8???????? }
            // n = 7, score = 100
            //   c744240808000000     | mov                 dword ptr [esp + 8], 8
            //   c744240cff000000     | mov                 dword ptr [esp + 0xc], 0xff
            //   ff15????????         |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   6a00                 | push                0
            //   e8????????           |                     

    condition:
        7 of them and filesize < 3580928
}