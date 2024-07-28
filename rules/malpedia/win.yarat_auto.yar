rule win_yarat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.yarat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yarat"
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
        $sequence_0 = { e8???????? 8b75a8 8bf8 3bf7 7465 8b4e14 83f910 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b75a8               | mov                 esi, dword ptr [ebp - 0x58]
            //   8bf8                 | mov                 edi, eax
            //   3bf7                 | cmp                 esi, edi
            //   7465                 | je                  0x67
            //   8b4e14               | mov                 ecx, dword ptr [esi + 0x14]
            //   83f910               | cmp                 ecx, 0x10

        $sequence_1 = { c70000000200 e9???????? 56 68???????? 57 e8???????? 83c40c }
            // n = 7, score = 100
            //   c70000000200         | mov                 dword ptr [eax], 0x20000
            //   e9????????           |                     
            //   56                   | push                esi
            //   68????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_2 = { 8d8544feffff 6a00 57 89864c010000 e8???????? 83c414 80bf0b05000000 }
            // n = 7, score = 100
            //   8d8544feffff         | lea                 eax, [ebp - 0x1bc]
            //   6a00                 | push                0
            //   57                   | push                edi
            //   89864c010000         | mov                 dword ptr [esi + 0x14c], eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   80bf0b05000000       | cmp                 byte ptr [edi + 0x50b], 0

        $sequence_3 = { e8???????? 83c40c 85d2 0f8f28010000 7c08 85c0 0f831e010000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85d2                 | test                edx, edx
            //   0f8f28010000         | jg                  0x12e
            //   7c08                 | jl                  0xa
            //   85c0                 | test                eax, eax
            //   0f831e010000         | jae                 0x124

        $sequence_4 = { 8b8f90050000 83c40c 85c9 7506 8b8f04030000 8b8748050000 8b4040 }
            // n = 7, score = 100
            //   8b8f90050000         | mov                 ecx, dword ptr [edi + 0x590]
            //   83c40c               | add                 esp, 0xc
            //   85c9                 | test                ecx, ecx
            //   7506                 | jne                 8
            //   8b8f04030000         | mov                 ecx, dword ptr [edi + 0x304]
            //   8b8748050000         | mov                 eax, dword ptr [edi + 0x548]
            //   8b4040               | mov                 eax, dword ptr [eax + 0x40]

        $sequence_5 = { 8a18 885dfe 80fb2e 8b5d08 7406 807dfe2c 7534 }
            // n = 7, score = 100
            //   8a18                 | mov                 bl, byte ptr [eax]
            //   885dfe               | mov                 byte ptr [ebp - 2], bl
            //   80fb2e               | cmp                 bl, 0x2e
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   7406                 | je                  8
            //   807dfe2c             | cmp                 byte ptr [ebp - 2], 0x2c
            //   7534                 | jne                 0x36

        $sequence_6 = { 07 20c2 aa 709a 93 a3???????? 9e }
            // n = 7, score = 100
            //   07                   | pop                 es
            //   20c2                 | and                 dl, al
            //   aa                   | stosb               byte ptr es:[edi], al
            //   709a                 | jo                  0xffffff9c
            //   93                   | xchg                eax, ebx
            //   a3????????           |                     
            //   9e                   | sahf                

        $sequence_7 = { 8b75fc 8bc7 c1e808 83e00f 8a80d0070a10 880433 8bda }
            // n = 7, score = 100
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   8bc7                 | mov                 eax, edi
            //   c1e808               | shr                 eax, 8
            //   83e00f               | and                 eax, 0xf
            //   8a80d0070a10         | mov                 al, byte ptr [eax + 0x100a07d0]
            //   880433               | mov                 byte ptr [ebx + esi], al
            //   8bda                 | mov                 ebx, edx

        $sequence_8 = { e8???????? 83c408 85c0 7405 8d7728 eb38 8d85fcefffff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   8d7728               | lea                 esi, [edi + 0x28]
            //   eb38                 | jmp                 0x3a
            //   8d85fcefffff         | lea                 eax, [ebp - 0x1004]

        $sequence_9 = { 8b4508 33f6 83f8ff 742d 8d8df4fdffff 51 50 }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   33f6                 | xor                 esi, esi
            //   83f8ff               | cmp                 eax, -1
            //   742d                 | je                  0x2f
            //   8d8df4fdffff         | lea                 ecx, [ebp - 0x20c]
            //   51                   | push                ecx
            //   50                   | push                eax

    condition:
        7 of them and filesize < 8692736
}