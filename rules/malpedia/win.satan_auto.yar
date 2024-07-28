rule win_satan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.satan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.satan"
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
        $sequence_0 = { e8???????? 8be5 5d c20800 8b45e4 c745b800000000 c745bc00000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   c745b800000000       | mov                 dword ptr [ebp - 0x48], 0
            //   c745bc00000000       | mov                 dword ptr [ebp - 0x44], 0

        $sequence_1 = { 52 ff15???????? 8b4508 8b0c85e8c24700 83e102 740d 8d95e4dfffff }
            // n = 7, score = 100
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b0c85e8c24700       | mov                 ecx, dword ptr [eax*4 + 0x47c2e8]
            //   83e102               | and                 ecx, 2
            //   740d                 | je                  0xf
            //   8d95e4dfffff         | lea                 edx, [ebp - 0x201c]

        $sequence_2 = { ffb5c4e7ffff 8985a0e7ffff ffb5bce7ffff c745ec04000000 }
            // n = 4, score = 100
            //   ffb5c4e7ffff         | push                dword ptr [ebp - 0x183c]
            //   8985a0e7ffff         | mov                 dword ptr [ebp - 0x1860], eax
            //   ffb5bce7ffff         | push                dword ptr [ebp - 0x1844]
            //   c745ec04000000       | mov                 dword ptr [ebp - 0x14], 4

        $sequence_3 = { 57 50 8d45f4 64a300000000 8d4dd0 e8???????? }
            // n = 6, score = 100
            //   57                   | push                edi
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   e8????????           |                     

        $sequence_4 = { e8???????? 8b85acfeffff 83f810 7212 40 6a01 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b85acfeffff         | mov                 eax, dword ptr [ebp - 0x154]
            //   83f810               | cmp                 eax, 0x10
            //   7212                 | jb                  0x14
            //   40                   | inc                 eax
            //   6a01                 | push                1

        $sequence_5 = { eb9b 8b4dfc c1f906 8b55fc 83e23f 6bc230 03048d40e04700 }
            // n = 7, score = 100
            //   eb9b                 | jmp                 0xffffff9d
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   c1f906               | sar                 ecx, 6
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   83e23f               | and                 edx, 0x3f
            //   6bc230               | imul                eax, edx, 0x30
            //   03048d40e04700       | add                 eax, dword ptr [ecx*4 + 0x47e040]

        $sequence_6 = { e8???????? 8845dc c745fc01000000 84c0 0f84b3010000 8d45d0 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8845dc               | mov                 byte ptr [ebp - 0x24], al
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   84c0                 | test                al, al
            //   0f84b3010000         | je                  0x1b9
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   50                   | push                eax

        $sequence_7 = { 8d0c8584d64700 51 e8???????? 83c408 }
            // n = 4, score = 100
            //   8d0c8584d64700       | lea                 ecx, [eax*4 + 0x47d684]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_8 = { 64a300000000 68b8000000 8d8598fdffff 6a00 50 e8???????? 68???????? }
            // n = 7, score = 100
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   68b8000000           | push                0xb8
            //   8d8598fdffff         | lea                 eax, [ebp - 0x268]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   68????????           |                     

        $sequence_9 = { 8b5508 83e23f 6bd230 8b0c8d40e04700 8844112d 8b45ec d1e0 }
            // n = 7, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   83e23f               | and                 edx, 0x3f
            //   6bd230               | imul                edx, edx, 0x30
            //   8b0c8d40e04700       | mov                 ecx, dword ptr [ecx*4 + 0x47e040]
            //   8844112d             | mov                 byte ptr [ecx + edx + 0x2d], al
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   d1e0                 | shl                 eax, 1

    condition:
        7 of them and filesize < 1163264
}