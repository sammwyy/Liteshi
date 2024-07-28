rule win_decaf_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.decaf."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.decaf"
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
        $sequence_0 = { e8???????? e8???????? 48898424a8180000 48899c2440060000 488b0d???????? 48898c2420230000 488d0543040c00 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   e8????????           |                     
            //   48898424a8180000     | dec                 eax
            //   48899c2440060000     | mov                 dword ptr [esp + 0x62], edx
            //   488b0d????????       |                     
            //   48898c2420230000     | dec                 ebp
            //   488d0543040c00       | cmp                 esp, dword ptr [esi + 0x10]

        $sequence_1 = { 4c8b442470 4889c7 4889ce 488b442440 c7041fcacccec6 b905000000 e9???????? }
            // n = 7, score = 100
            //   4c8b442470           | dec                 eax
            //   4889c7               | lea                 edi, [0x1fa243]
            //   4889ce               | dec                 eax
            //   488b442440           | mov                 dword ptr [esp + 0x1848], eax
            //   c7041fcacccec6       | dec                 eax
            //   b905000000           | mov                 dword ptr [esp + 0x678], ebx
            //   e9????????           |                     

        $sequence_2 = { e9???????? 4c8d4302 4c39c6 7337 4c89442468 488d05d8a30300 4889d9 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   4c8d4302             | mov                 word ptr [edi + ebx], 0x28
            //   4c39c6               | mov                 byte ptr [edi + ebx + 2], 0x1e
            //   7337                 | mov                 ecx, 1
            //   4c89442468           | nop                 dword ptr [eax + eax]
            //   488d05d8a30300       | dec                 ecx
            //   4889d9               | cmp                 eax, 1

        $sequence_3 = { c3 488d0582761b00 bb10000000 e8???????? 4889f8 b900200000 e8???????? }
            // n = 7, score = 100
            //   c3                   | mov                 esi, eax
            //   488d0582761b00       | nop                 dword ptr [eax]
            //   bb10000000           | dec                 esp
            //   e8????????           |                     
            //   4889f8               | mov                 dword ptr [esp + 0x78], eax
            //   b900200000           | dec                 eax
            //   e8????????           |                     

        $sequence_4 = { e8???????? 488b8c24b8040000 48894808 833d????????00 7514 488b8c2410160000 488908 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b8c24b8040000     | cmp                 esi, eax
            //   48894808             | jae                 0x1546
            //   833d????????00       |                     
            //   7514                 | dec                 eax
            //   488b8c2410160000     | lea                 eax, [0xf0cca]
            //   488908               | dec                 eax

        $sequence_5 = { eb1c 4889c7 488b8c24f0120000 e8???????? 488d3d53871f00 e8???????? e8???????? }
            // n = 7, score = 100
            //   eb1c                 | dec                 eax
            //   4889c7               | mov                 edi, esi
            //   488b8c24f0120000     | dec                 esp
            //   e8????????           |                     
            //   488d3d53871f00       | mov                 esi, eax
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_6 = { e8???????? 488d05d4ad1300 488d1d95d21900 e8???????? 4d8d6830 4c89d6 4d89ea }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d05d4ad1300       | cmp                 esi, eax
            //   488d1d95d21900       | jae                 0x13e3
            //   e8????????           |                     
            //   4d8d6830             | dec                 esp
            //   4c89d6               | mov                 dword ptr [esp + 0x60], eax
            //   4d89ea               | dec                 eax

        $sequence_7 = { e9???????? 90 66c744244f1c14 0fb654244f 88542445 440fb6442450 4488442444 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   90                   | mov                 word ptr [edi + ebx], 0x8884
            //   66c744244f1c14       | mov                 byte ptr [edi + ebx + 2], 0x84
            //   0fb654244f           | mov                 ecx, 3
            //   88542445             | dec                 esp
            //   440fb6442450         | lea                 eax, [ebx + 1]
            //   4488442444           | nop                 

        $sequence_8 = { c6041f95 31c9 e9???????? 4983f809 754d 4c8d4301 4c39c6 }
            // n = 7, score = 100
            //   c6041f95             | dec                 eax
            //   31c9                 | mov                 ecx, ebx
            //   e9????????           |                     
            //   4983f809             | dec                 eax
            //   754d                 | mov                 ebx, edi
            //   4c8d4301             | dec                 eax
            //   4c39c6               | mov                 edi, esi

        $sequence_9 = { e9???????? 48895c2428 4889442430 488d0d664c1d00 bf0d000000 e8???????? 4885c0 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   48895c2428           | dec                 esp
            //   4889442430           | lea                 eax, [ebx + 4]
            //   488d0d664c1d00       | dec                 esp
            //   bf0d000000           | cmp                 esi, eax
            //   e8????????           |                     
            //   4885c0               | jae                 0x1a6b

    condition:
        7 of them and filesize < 7193600
}