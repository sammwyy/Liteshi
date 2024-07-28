rule win_mail_o_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.mail_o."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mail_o"
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
        $sequence_0 = { 7707 33c0 e9???????? f683a414000020 7417 8b83700e0000 2500000100 }
            // n = 7, score = 100
            //   7707                 | dec                 eax
            //   33c0                 | mov                 ecx, esi
            //   e9????????           |                     
            //   f683a414000020       | dec                 eax
            //   7417                 | mov                 edx, esi
            //   8b83700e0000         | dec                 eax
            //   2500000100           | mov                 dword ptr [esi + 0x10], edi

        $sequence_1 = { f20f104c2450 f20f114930 83cbff 8b0f e8???????? 8bc3 488b5c2470 }
            // n = 7, score = 100
            //   f20f104c2450         | shr                 eax, 0xd
            //   f20f114930           | and                 eax, 1
            //   83cbff               | dec                 eax
            //   8b0f                 | mov                 ebx, dword ptr [esp + 0x40]
            //   e8????????           |                     
            //   8bc3                 | dec                 eax
            //   488b5c2470           | mov                 esi, dword ptr [esp + 0x48]

        $sequence_2 = { eb0c 488d15b7940d00 e8???????? 488b4708 488d542440 448b4710 33c9 }
            // n = 7, score = 100
            //   eb0c                 | dec                 esp
            //   488d15b7940d00       | lea                 ecx, [0x14b4ed]
            //   e8????????           |                     
            //   488b4708             | dec                 eax
            //   488d542440           | mov                 ecx, ebx
            //   448b4710             | inc                 esp
            //   33c9                 | mov                 esi, eax

        $sequence_3 = { b920000000 ffcb ff542428 83f8ff 0f84b2010000 ffc7 85db }
            // n = 7, score = 100
            //   b920000000           | dec                 eax
            //   ffcb                 | mov                 ecx, ebx
            //   ff542428             | dec                 eax
            //   83f8ff               | mov                 dword ptr [esp + 0x40], eax
            //   0f84b2010000         | dec                 eax
            //   ffc7                 | lea                 ecx, [esi + 0x728]
            //   85db                 | inc                 ecx

        $sequence_4 = { 8b5c2438 418d7f10 4533c0 498bce 3bfb 7e23 488d542440 }
            // n = 7, score = 100
            //   8b5c2438             | test                edx, edx
            //   418d7f10             | je                  0xf00
            //   4533c0               | cmp                 byte ptr [ebx + 0x58], 0
            //   498bce               | je                  0xe29
            //   3bfb                 | dec                 eax
            //   7e23                 | test                eax, eax
            //   488d542440           | je                  0x1121

        $sequence_5 = { e8???????? eb17 498b4d10 4d8bf4 418bdc e8???????? eb06 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   eb17                 | test                cl, 8
            //   498b4d10             | dec                 eax
            //   4d8bf4               | mov                 ecx, dword ptr [edi + 0x100]
            //   418bdc               | test                eax, eax
            //   e8????????           |                     
            //   eb06                 | je                  0x13f8

        $sequence_6 = { c744242071000000 448d4041 eb1f 488918 488bd0 488b4d08 e8???????? }
            // n = 7, score = 100
            //   c744242071000000     | dec                 eax
            //   448d4041             | lea                 ecx, [ebx + 0x478]
            //   eb1f                 | dec                 eax
            //   488918               | mov                 dword ptr [ebx + 0xc0], edi
            //   488bd0               | dec                 eax
            //   488b4d08             | mov                 ecx, dword ptr [ebx + 0xe0]
            //   e8????????           |                     

        $sequence_7 = { 85c0 743c 48ffc3 483b5c2430 72c3 488bcf e8???????? }
            // n = 7, score = 100
            //   85c0                 | dec                 eax
            //   743c                 | test                ecx, ecx
            //   48ffc3               | js                  0x1b98
            //   483b5c2430           | dec                 eax
            //   72c3                 | cmp                 dword ptr [esi + 0xf8], edi
            //   488bcf               | je                  0x1b08
            //   e8????????           |                     

        $sequence_8 = { 84c0 7465 48ffc1 498d0408 483bc2 72df ba00800000 }
            // n = 7, score = 100
            //   84c0                 | sub                 esp, eax
            //   7465                 | dec                 eax
            //   48ffc1               | xor                 eax, esp
            //   498d0408             | dec                 eax
            //   483bc2               | mov                 dword ptr [esp + 0x58], eax
            //   72df                 | movzx               ebp, byte ptr [ecx]
            //   ba00800000           | dec                 ecx

        $sequence_9 = { e8???????? 8bf8 85c0 7556 48837c245000 7505 8d7809 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bf8                 | mov                 ecx, dword ptr [ebx + 0x88]
            //   85c0                 | dec                 eax
            //   7556                 | mov                 ecx, dword ptr [ebx + 0x110]
            //   48837c245000         | dec                 eax
            //   7505                 | mov                 ecx, dword ptr [ebx + 0x118]
            //   8d7809               | dec                 eax

    condition:
        7 of them and filesize < 5985280
}