rule win_unidentified_039_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_039."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_039"
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
        $sequence_0 = { b8???????? e8???????? 8365fc00 8365cc00 c745dce7600000 c745ec89640000 }
            // n = 6, score = 100
            //   b8????????           |                     
            //   e8????????           |                     
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   8365cc00             | and                 dword ptr [ebp - 0x34], 0
            //   c745dce7600000       | mov                 dword ptr [ebp - 0x24], 0x60e7
            //   c745ec89640000       | mov                 dword ptr [ebp - 0x14], 0x6489

        $sequence_1 = { c745f00b090000 c745f089000000 8975c0 c745f4b76e0000 c745fc9e540000 c745f8a7600000 }
            // n = 6, score = 100
            //   c745f00b090000       | mov                 dword ptr [ebp - 0x10], 0x90b
            //   c745f089000000       | mov                 dword ptr [ebp - 0x10], 0x89
            //   8975c0               | mov                 dword ptr [ebp - 0x40], esi
            //   c745f4b76e0000       | mov                 dword ptr [ebp - 0xc], 0x6eb7
            //   c745fc9e540000       | mov                 dword ptr [ebp - 4], 0x549e
            //   c745f8a7600000       | mov                 dword ptr [ebp - 8], 0x60a7

        $sequence_2 = { c74530284c0000 c7453425120000 c745281f480000 c74538136b0000 c74520825d0000 c7451c84360000 8b4530 }
            // n = 7, score = 100
            //   c74530284c0000       | mov                 dword ptr [ebp + 0x30], 0x4c28
            //   c7453425120000       | mov                 dword ptr [ebp + 0x34], 0x1225
            //   c745281f480000       | mov                 dword ptr [ebp + 0x28], 0x481f
            //   c74538136b0000       | mov                 dword ptr [ebp + 0x38], 0x6b13
            //   c74520825d0000       | mov                 dword ptr [ebp + 0x20], 0x5d82
            //   c7451c84360000       | mov                 dword ptr [ebp + 0x1c], 0x3684
            //   8b4530               | mov                 eax, dword ptr [ebp + 0x30]

        $sequence_3 = { 69c9de3f0000 33c1 8945dc 8b4510 8b4d0c 3bc8 7d0c }
            // n = 7, score = 100
            //   69c9de3f0000         | imul                ecx, ecx, 0x3fde
            //   33c1                 | xor                 eax, ecx
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   3bc8                 | cmp                 ecx, eax
            //   7d0c                 | jge                 0xe

        $sequence_4 = { 8bec 51 51 c745f81d2d0000 c745f8d33a0000 c745fc9a790000 }
            // n = 6, score = 100
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   c745f81d2d0000       | mov                 dword ptr [ebp - 8], 0x2d1d
            //   c745f8d33a0000       | mov                 dword ptr [ebp - 8], 0x3ad3
            //   c745fc9a790000       | mov                 dword ptr [ebp - 4], 0x799a

        $sequence_5 = { c745d0e5720000 8b45d0 8b4dd4 0fafc1 8b4dd8 8b55dc }
            // n = 6, score = 100
            //   c745d0e5720000       | mov                 dword ptr [ebp - 0x30], 0x72e5
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   0fafc1               | imul                eax, ecx
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]

        $sequence_6 = { 6bc01f c1e704 83c30c 03fa 33d2 }
            // n = 5, score = 100
            //   6bc01f               | imul                eax, eax, 0x1f
            //   c1e704               | shl                 edi, 4
            //   83c30c               | add                 ebx, 0xc
            //   03fa                 | add                 edi, edx
            //   33d2                 | xor                 edx, edx

        $sequence_7 = { 69c0295a0000 8945e4 e8???????? c745e0f9750000 c745f0b56c0000 c745ec29110000 }
            // n = 6, score = 100
            //   69c0295a0000         | imul                eax, eax, 0x5a29
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   e8????????           |                     
            //   c745e0f9750000       | mov                 dword ptr [ebp - 0x20], 0x75f9
            //   c745f0b56c0000       | mov                 dword ptr [ebp - 0x10], 0x6cb5
            //   c745ec29110000       | mov                 dword ptr [ebp - 0x14], 0x1129

        $sequence_8 = { 8d45f4 64a300000000 c3 6a00 6a01 ff74240c }
            // n = 6, score = 100
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   c3                   | ret                 
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   ff74240c             | push                dword ptr [esp + 0xc]

        $sequence_9 = { c745e863430000 8b45e4 59 8b4df8 23c1 8b4de8 81e931570000 }
            // n = 7, score = 100
            //   c745e863430000       | mov                 dword ptr [ebp - 0x18], 0x4363
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   59                   | pop                 ecx
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   23c1                 | and                 eax, ecx
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   81e931570000         | sub                 ecx, 0x5731

    condition:
        7 of them and filesize < 262144
}