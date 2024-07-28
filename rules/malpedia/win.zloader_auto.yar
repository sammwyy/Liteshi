rule win_zloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.zloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zloader"
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
        $sequence_0 = { 57 6a01 56 ffd0 89f7 89f8 }
            // n = 6, score = 2000
            //   57                   | push                edi
            //   6a01                 | push                1
            //   56                   | push                esi
            //   ffd0                 | call                eax
            //   89f7                 | mov                 edi, esi
            //   89f8                 | mov                 eax, edi

        $sequence_1 = { 57 56 83ec0c 8b5d0c 8b7d10 8d75e8 89f1 }
            // n = 7, score = 2000
            //   57                   | push                edi
            //   56                   | push                esi
            //   83ec0c               | sub                 esp, 0xc
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   8d75e8               | lea                 esi, [ebp - 0x18]
            //   89f1                 | mov                 ecx, esi

        $sequence_2 = { 55 89e5 56 8b7508 ff36 e8???????? 83c404 }
            // n = 7, score = 2000
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   ff36                 | push                dword ptr [esi]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_3 = { 0fb7450c 8d9df0feffff 53 50 ff7508 e8???????? }
            // n = 6, score = 2000
            //   0fb7450c             | movzx               eax, word ptr [ebp + 0xc]
            //   8d9df0feffff         | lea                 ebx, [ebp - 0x110]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_4 = { 57 56 8b7d08 57 e8???????? }
            // n = 5, score = 2000
            //   57                   | push                edi
            //   56                   | push                esi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_5 = { 0fb7c0 57 50 53 e8???????? 83c40c 89f1 }
            // n = 7, score = 2000
            //   0fb7c0               | movzx               eax, ax
            //   57                   | push                edi
            //   50                   | push                eax
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   89f1                 | mov                 ecx, esi

        $sequence_6 = { 53 56 83ec0c 8d75ec 56 6aff }
            // n = 6, score = 2000
            //   53                   | push                ebx
            //   56                   | push                esi
            //   83ec0c               | sub                 esp, 0xc
            //   8d75ec               | lea                 esi, [ebp - 0x14]
            //   56                   | push                esi
            //   6aff                 | push                -1

        $sequence_7 = { 55 89e5 56 8b750c ff7508 e8???????? 83c404 }
            // n = 7, score = 2000
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_8 = { 56 50 a1???????? 89c1 }
            // n = 4, score = 1300
            //   56                   | push                esi
            //   50                   | push                eax
            //   a1????????           |                     
            //   89c1                 | mov                 ecx, eax

        $sequence_9 = { 5e 8bc3 5b c3 8b44240c }
            // n = 5, score = 700
            //   5e                   | pop                 esi
            //   8bc3                 | mov                 eax, ebx
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]

        $sequence_10 = { 68???????? ff742408 e8???????? 59 59 84c0 741e }
            // n = 7, score = 700
            //   68????????           |                     
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   84c0                 | test                al, al
            //   741e                 | je                  0x20

        $sequence_11 = { e8???????? 59 84c0 7432 68???????? ff742408 e8???????? }
            // n = 7, score = 700
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   84c0                 | test                al, al
            //   7432                 | je                  0x34
            //   68????????           |                     
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     

        $sequence_12 = { 57 56 50 8b4510 31db }
            // n = 5, score = 700
            //   57                   | push                edi
            //   56                   | push                esi
            //   50                   | push                eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   31db                 | xor                 ebx, ebx

        $sequence_13 = { e8???????? 03c0 6689442438 8b442438 }
            // n = 4, score = 600
            //   e8????????           |                     
            //   03c0                 | add                 eax, eax
            //   6689442438           | mov                 word ptr [esp + 0x38], ax
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]

        $sequence_14 = { 6aff 50 e8???????? 8d857cffffff 50 }
            // n = 5, score = 600
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d857cffffff         | lea                 eax, [ebp - 0x84]
            //   50                   | push                eax

        $sequence_15 = { 50 89542444 e8???????? 03c0 }
            // n = 4, score = 600
            //   50                   | push                eax
            //   89542444             | mov                 dword ptr [esp + 0x44], edx
            //   e8????????           |                     
            //   03c0                 | add                 eax, eax

        $sequence_16 = { 6689442438 8b442438 83c002 668944243a }
            // n = 4, score = 600
            //   6689442438           | mov                 word ptr [esp + 0x38], ax
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]
            //   83c002               | add                 eax, 2
            //   668944243a           | mov                 word ptr [esp + 0x3a], ax

        $sequence_17 = { 83c414 c3 56 ff742410 }
            // n = 4, score = 600
            //   83c414               | add                 esp, 0x14
            //   c3                   | ret                 
            //   56                   | push                esi
            //   ff742410             | push                dword ptr [esp + 0x10]

        $sequence_18 = { 99 52 50 8d44243c 99 52 50 }
            // n = 7, score = 600
            //   99                   | cdq                 
            //   52                   | push                edx
            //   50                   | push                eax
            //   8d44243c             | lea                 eax, [esp + 0x3c]
            //   99                   | cdq                 
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_19 = { c6043000 5e c3 56 57 8b7c2414 83ffff }
            // n = 7, score = 600
            //   c6043000             | mov                 byte ptr [eax + esi], 0
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7c2414             | mov                 edi, dword ptr [esp + 0x14]
            //   83ffff               | cmp                 edi, -1

        $sequence_20 = { 50 56 56 56 ff7514 }
            // n = 5, score = 600
            //   50                   | push                eax
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi
            //   ff7514               | push                dword ptr [ebp + 0x14]

        $sequence_21 = { 83c408 5e 5d c3 55 89e5 57 }
            // n = 7, score = 500
            //   83c408               | add                 esp, 8
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   57                   | push                edi

        $sequence_22 = { 6a00 e8???????? 83c414 c3 8b542404 }
            // n = 5, score = 500
            //   6a00                 | push                0
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   c3                   | ret                 
            //   8b542404             | mov                 edx, dword ptr [esp + 4]

        $sequence_23 = { c7462401000000 c7462800004001 e8???????? 89460c }
            // n = 4, score = 500
            //   c7462401000000       | mov                 dword ptr [esi + 0x24], 1
            //   c7462800004001       | mov                 dword ptr [esi + 0x28], 0x1400000
            //   e8????????           |                     
            //   89460c               | mov                 dword ptr [esi + 0xc], eax

        $sequence_24 = { 81c4a8020000 5e 5f 5b }
            // n = 4, score = 500
            //   81c4a8020000         | add                 esp, 0x2a8
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx

        $sequence_25 = { 55 89e5 53 57 56 81eca8020000 }
            // n = 6, score = 500
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   81eca8020000         | sub                 esp, 0x2a8

        $sequence_26 = { e9???????? 31c0 83c40c 5e 5f }
            // n = 5, score = 500
            //   e9????????           |                     
            //   31c0                 | xor                 eax, eax
            //   83c40c               | add                 esp, 0xc
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi

        $sequence_27 = { 0bc3 a3???????? e8???????? 8bc8 eb06 8b0d???????? 85c9 }
            // n = 7, score = 500
            //   0bc3                 | or                  eax, ebx
            //   a3????????           |                     
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   eb06                 | jmp                 8
            //   8b0d????????         |                     
            //   85c9                 | test                ecx, ecx

        $sequence_28 = { 89b42430010000 8b842430010000 8b842430010000 890424 c74424041c010000 e8???????? }
            // n = 6, score = 400
            //   89b42430010000       | mov                 dword ptr [esp + 0x130], esi
            //   8b842430010000       | mov                 eax, dword ptr [esp + 0x130]
            //   8b842430010000       | mov                 eax, dword ptr [esp + 0x130]
            //   890424               | mov                 dword ptr [esp], eax
            //   c74424041c010000     | mov                 dword ptr [esp + 4], 0x11c
            //   e8????????           |                     

        $sequence_29 = { 89cf 8d0476 8945ec 890424 }
            // n = 4, score = 400
            //   89cf                 | mov                 edi, ecx
            //   8d0476               | lea                 eax, [esi + esi*2]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_30 = { 50 6a72 e8???????? 59 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   6a72                 | push                0x72
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_31 = { 56 57 ff750c 33db 68???????? 6880000000 50 }
            // n = 7, score = 300
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   33db                 | xor                 ebx, ebx
            //   68????????           |                     
            //   6880000000           | push                0x80
            //   50                   | push                eax

        $sequence_32 = { 8bc2 ebf7 8d442410 50 ff742410 ff742410 ff742410 }
            // n = 7, score = 300
            //   8bc2                 | mov                 eax, edx
            //   ebf7                 | jmp                 0xfffffff9
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   ff742410             | push                dword ptr [esp + 0x10]

        $sequence_33 = { 56 68???????? ff742410 e8???????? 6823af2930 56 ff742410 }
            // n = 7, score = 300
            //   56                   | push                esi
            //   68????????           |                     
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   e8????????           |                     
            //   6823af2930           | push                0x3029af23
            //   56                   | push                esi
            //   ff742410             | push                dword ptr [esp + 0x10]

        $sequence_34 = { 50 e8???????? 68???????? 56 e8???????? 8bf0 59 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx

        $sequence_35 = { 5f 5e 5b c3 8bc2 ebf8 53 }
            // n = 7, score = 300
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8bc2                 | mov                 eax, edx
            //   ebf8                 | jmp                 0xfffffffa
            //   53                   | push                ebx

        $sequence_36 = { 33f6 e8???????? ff7508 8d85f0fdffff 68???????? }
            // n = 5, score = 300
            //   33f6                 | xor                 esi, esi
            //   e8????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   68????????           |                     

        $sequence_37 = { 68???????? 56 e8???????? 5e c3 56 }
            // n = 6, score = 300
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   56                   | push                esi

        $sequence_38 = { 8d85f0fdffff 68???????? 6804010000 50 e8???????? 83c414 8d45fc }
            // n = 7, score = 300
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   68????????           |                     
            //   6804010000           | push                0x104
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8d45fc               | lea                 eax, [ebp - 4]

        $sequence_39 = { 8bc2 ebf8 53 8b5c240c 55 33ed }
            // n = 6, score = 300
            //   8bc2                 | mov                 eax, edx
            //   ebf8                 | jmp                 0xfffffffa
            //   53                   | push                ebx
            //   8b5c240c             | mov                 ebx, dword ptr [esp + 0xc]
            //   55                   | push                ebp
            //   33ed                 | xor                 ebp, ebp

    condition:
        7 of them and filesize < 1105920
}