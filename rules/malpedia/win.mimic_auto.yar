rule win_mimic_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.mimic."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mimic"
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
        $sequence_0 = { 7f4a 7c05 3945e0 7343 8b55dc 83fa08 0f82b4000000 }
            // n = 7, score = 100
            //   7f4a                 | jg                  0x4c
            //   7c05                 | jl                  7
            //   3945e0               | cmp                 dword ptr [ebp - 0x20], eax
            //   7343                 | jae                 0x45
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   83fa08               | cmp                 edx, 8
            //   0f82b4000000         | jb                  0xba

        $sequence_1 = { 81fe2c010000 7f1d 68e8030000 ffd7 ffd3 85c0 74dd }
            // n = 7, score = 100
            //   81fe2c010000         | cmp                 esi, 0x12c
            //   7f1d                 | jg                  0x1f
            //   68e8030000           | push                0x3e8
            //   ffd7                 | call                edi
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   74dd                 | je                  0xffffffdf

        $sequence_2 = { 837db810 51 0f4345a4 8d4d84 03c2 50 e8???????? }
            // n = 7, score = 100
            //   837db810             | cmp                 dword ptr [ebp - 0x48], 0x10
            //   51                   | push                ecx
            //   0f4345a4             | cmovae              eax, dword ptr [ebp - 0x5c]
            //   8d4d84               | lea                 ecx, [ebp - 0x7c]
            //   03c2                 | add                 eax, edx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { a3???????? 8b8548feffff 894804 8d8d30feffff e8???????? 6a20 ffb530feffff }
            // n = 7, score = 100
            //   a3????????           |                     
            //   8b8548feffff         | mov                 eax, dword ptr [ebp - 0x1b8]
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   8d8d30feffff         | lea                 ecx, [ebp - 0x1d0]
            //   e8????????           |                     
            //   6a20                 | push                0x20
            //   ffb530feffff         | push                dword ptr [ebp - 0x1d0]

        $sequence_4 = { 0f43c2 0f43da 8d0470 8db5ccfdffff 8bc8 0f43f2 33ff }
            // n = 7, score = 100
            //   0f43c2               | cmovae              eax, edx
            //   0f43da               | cmovae              ebx, edx
            //   8d0470               | lea                 eax, [eax + esi*2]
            //   8db5ccfdffff         | lea                 esi, [ebp - 0x234]
            //   8bc8                 | mov                 ecx, eax
            //   0f43f2               | cmovae              esi, edx
            //   33ff                 | xor                 edi, edi

        $sequence_5 = { 42 41 3bd6 7cf4 3bd6 751f 6a61 }
            // n = 7, score = 100
            //   42                   | inc                 edx
            //   41                   | inc                 ecx
            //   3bd6                 | cmp                 edx, esi
            //   7cf4                 | jl                  0xfffffff6
            //   3bd6                 | cmp                 edx, esi
            //   751f                 | jne                 0x21
            //   6a61                 | push                0x61

        $sequence_6 = { c745fc02000000 a801 743a 83e0fe 894584 83ff08 }
            // n = 6, score = 100
            //   c745fc02000000       | mov                 dword ptr [ebp - 4], 2
            //   a801                 | test                al, 1
            //   743a                 | je                  0x3c
            //   83e0fe               | and                 eax, 0xfffffffe
            //   894584               | mov                 dword ptr [ebp - 0x7c], eax
            //   83ff08               | cmp                 edi, 8

        $sequence_7 = { 50 ffd6 68???????? c645fc40 e8???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   c645fc40             | mov                 byte ptr [ebp - 4], 0x40
            //   e8????????           |                     

        $sequence_8 = { 8d8d18ffffff e9???????? 8d4dc0 e9???????? 8d4dd8 e9???????? 8b542408 }
            // n = 7, score = 100
            //   8d8d18ffffff         | lea                 ecx, [ebp - 0xe8]
            //   e9????????           |                     
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]
            //   e9????????           |                     
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e9????????           |                     
            //   8b542408             | mov                 edx, dword ptr [esp + 8]

        $sequence_9 = { 8b483c 898424e4000000 89ac24e0000000 894c2438 0f1f4000 0f1f840000000000 8bb424fc010000 }
            // n = 7, score = 100
            //   8b483c               | mov                 ecx, dword ptr [eax + 0x3c]
            //   898424e4000000       | mov                 dword ptr [esp + 0xe4], eax
            //   89ac24e0000000       | mov                 dword ptr [esp + 0xe0], ebp
            //   894c2438             | mov                 dword ptr [esp + 0x38], ecx
            //   0f1f4000             | nop                 dword ptr [eax]
            //   0f1f840000000000     | nop                 dword ptr [eax + eax]
            //   8bb424fc010000       | mov                 esi, dword ptr [esp + 0x1fc]

    condition:
        7 of them and filesize < 4204544
}