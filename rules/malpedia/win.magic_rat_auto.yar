rule win_magic_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.magic_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.magic_rat"
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
        $sequence_0 = { 85c0 7407 3dffff0000 756f }
            // n = 4, score = 600
            //   85c0                 | je                  0xffffff92
            //   7407                 | lock sub            dword ptr [ecx], 1
            //   3dffff0000           | je                  0x4a
            //   756f                 | mov                 ecx, dword ptr [esi]

        $sequence_1 = { f20f2ac9 f20f5cc1 f20f58c3 f20f2cc0 }
            // n = 4, score = 600
            //   f20f2ac9             | mov                 eax, dword ptr [esi]
            //   f20f5cc1             | mov                 dword ptr [eax + 0x20], 0x146d7a0
            //   f20f58c3             | mov                 dword ptr [eax + 0x24], 0x146d7a0
            //   f20f2cc0             | mov                 dword ptr [eax + 0x28], 0x146d7a0

        $sequence_2 = { 0f84b8000000 83faff 7408 f0830001 }
            // n = 4, score = 600
            //   0f84b8000000         | dec                 esp
            //   83faff               | cmp                 ebp, edi
            //   7408                 | je                  0x99e
            //   f0830001             | cmp                 edx, -1

        $sequence_3 = { 660f2ec2 7308 660f5705???????? 660f2ee2 f20f59c5 7308 660f5725???????? }
            // n = 7, score = 600
            //   660f2ec2             | je                  0x1e48
            //   7308                 | dec                 ecx
            //   660f5705????????     |                     
            //   660f2ee2             | mov                 ecx, dword ptr [ebp + 0x10]
            //   f20f59c5             | dec                 eax
            //   7308                 | test                ecx, ecx
            //   660f5725????????     |                     

        $sequence_4 = { 29c2 89d0 c1f80e f7d8 eb08 }
            // n = 5, score = 600
            //   29c2                 | jne                 0xac7
            //   89d0                 | inc                 ecx
            //   c1f80e               | cmp                 edi, 1
            //   f7d8                 | jne                 0x12b7
            //   eb08                 | or                  bl, al

        $sequence_5 = { 8b01 81e20080ffff 25ff7f0000 09d0 }
            // n = 4, score = 600
            //   8b01                 | jmp                 0x119
            //   81e20080ffff         | cmp                 ebx, 4
            //   25ff7f0000           | jbe                 0x11c
            //   09d0                 | mov                 edx, dword ptr [esi + 0x10]

        $sequence_6 = { 8b4500 85c0 0f8472010000 83f8ff 740b f0836d0001 }
            // n = 6, score = 600
            //   8b4500               | movzx               eax, byte ptr [esp + 0x1b]
            //   85c0                 | add                 eax, edx
            //   0f8472010000         | mov                 edx, eax
            //   83f8ff               | shl                 edx, 5
            //   740b                 | sub                 edx, eax
            //   f0836d0001           | mov                 edx, eax

        $sequence_7 = { f20f58c3 f20f2cd0 01ca e9???????? }
            // n = 4, score = 600
            //   f20f58c3             | shl                 eax, 4
            //   f20f2cd0             | add                 edx, eax
            //   01ca                 | sub                 ecx, eax
            //   e9????????           |                     

        $sequence_8 = { 85d2 740b 83faff 74ad f0832801 }
            // n = 5, score = 600
            //   85d2                 | jl                  0x16c
            //   740b                 | test                al, al
            //   83faff               | jne                 0xe5
            //   74ad                 | dec                 eax
            //   f0832801             | lea                 ecx, [0xa862d4]

        $sequence_9 = { 81fa???????? 7442 81fa???????? 744a }
            // n = 4, score = 600
            //   81fa????????         |                     
            //   7442                 | movapd              xmm1, xmm0
            //   81fa????????         |                     
            //   744a                 | subsd               xmm1, xmm7

    condition:
        7 of them and filesize < 41843712
}