rule win_doublefantasy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.doublefantasy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doublefantasy"
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
        $sequence_0 = { ff75e0 e8???????? 8945c4 3d05000780 7458 3d09000c80 }
            // n = 6, score = 200
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   e8????????           |                     
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   3d05000780           | cmp                 eax, 0x80070005
            //   7458                 | je                  0x5a
            //   3d09000c80           | cmp                 eax, 0x800c0009

        $sequence_1 = { 770b 0fb6c0 8a80ad8c2700 eb02 32c0 84c0 7410 }
            // n = 7, score = 200
            //   770b                 | ja                  0xd
            //   0fb6c0               | movzx               eax, al
            //   8a80ad8c2700         | mov                 al, byte ptr [eax + 0x278cad]
            //   eb02                 | jmp                 4
            //   32c0                 | xor                 al, al
            //   84c0                 | test                al, al
            //   7410                 | je                  0x12

        $sequence_2 = { 8a80908c2700 eb02 b03d 884103 c3 55 }
            // n = 6, score = 200
            //   8a80908c2700         | mov                 al, byte ptr [eax + 0x278c90]
            //   eb02                 | jmp                 4
            //   b03d                 | mov                 al, 0x3d
            //   884103               | mov                 byte ptr [ecx + 3], al
            //   c3                   | ret                 
            //   55                   | push                ebp

        $sequence_3 = { 33d2 8a5001 c1ee06 83e20f c1e202 0bd6 8a92908c2700 }
            // n = 7, score = 200
            //   33d2                 | xor                 edx, edx
            //   8a5001               | mov                 dl, byte ptr [eax + 1]
            //   c1ee06               | shr                 esi, 6
            //   83e20f               | and                 edx, 0xf
            //   c1e202               | shl                 edx, 2
            //   0bd6                 | or                  edx, esi
            //   8a92908c2700         | mov                 dl, byte ptr [edx + 0x278c90]

        $sequence_4 = { ff750c 8b4622 03c6 50 e8???????? 83c40c be???????? }
            // n = 7, score = 200
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8b4622               | mov                 eax, dword ptr [esi + 0x22]
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   be????????           |                     

        $sequence_5 = { 51 68???????? ff750c 8b1d???????? ffd3 83c420 ff75e0 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   68????????           |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8b1d????????         |                     
            //   ffd3                 | call                ebx
            //   83c420               | add                 esp, 0x20
            //   ff75e0               | push                dword ptr [ebp - 0x20]

        $sequence_6 = { 8a92908c2700 885101 7e1c 0fb67002 }
            // n = 4, score = 200
            //   8a92908c2700         | mov                 dl, byte ptr [edx + 0x278c90]
            //   885101               | mov                 byte ptr [ecx + 1], dl
            //   7e1c                 | jle                 0x1e
            //   0fb67002             | movzx               esi, byte ptr [eax + 2]

        $sequence_7 = { ff45f8 3c2b 720f 3c7a 770b 0fb6c0 8a80ad8c2700 }
            // n = 7, score = 200
            //   ff45f8               | inc                 dword ptr [ebp - 8]
            //   3c2b                 | cmp                 al, 0x2b
            //   720f                 | jb                  0x11
            //   3c7a                 | cmp                 al, 0x7a
            //   770b                 | ja                  0xd
            //   0fb6c0               | movzx               eax, al
            //   8a80ad8c2700         | mov                 al, byte ptr [eax + 0x278cad]

        $sequence_8 = { 0bd6 837c241001 8a92908c2700 885101 }
            // n = 4, score = 200
            //   0bd6                 | or                  edx, esi
            //   837c241001           | cmp                 dword ptr [esp + 0x10], 1
            //   8a92908c2700         | mov                 dl, byte ptr [edx + 0x278c90]
            //   885101               | mov                 byte ptr [ecx + 1], dl

        $sequence_9 = { 8a92908c2700 eb02 b23d 837c241002 885102 }
            // n = 5, score = 200
            //   8a92908c2700         | mov                 dl, byte ptr [edx + 0x278c90]
            //   eb02                 | jmp                 4
            //   b23d                 | mov                 dl, 0x3d
            //   837c241002           | cmp                 dword ptr [esp + 0x10], 2
            //   885102               | mov                 byte ptr [ecx + 2], dl

        $sequence_10 = { 85c0 7c6a 8b45e4 8b08 8d954cffffff }
            // n = 5, score = 200
            //   85c0                 | test                eax, eax
            //   7c6a                 | jl                  0x6c
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8d954cffffff         | lea                 edx, [ebp - 0xb4]

        $sequence_11 = { e8???????? 8b4605 c68094a3270000 ff35???????? ff35???????? e8???????? 83c414 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b4605               | mov                 eax, dword ptr [esi + 5]
            //   c68094a3270000       | mov                 byte ptr [eax + 0x27a394], 0
            //   ff35????????         |                     
            //   ff35????????         |                     
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14

        $sequence_12 = { a5 a5 a5 66a5 6a3d 59 }
            // n = 6, score = 200
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]
            //   6a3d                 | push                0x3d
            //   59                   | pop                 ecx

        $sequence_13 = { 68???????? 68???????? ff15???????? 83c40c 837de000 0f8660010000 }
            // n = 6, score = 200
            //   68????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   837de000             | cmp                 dword ptr [ebp - 0x20], 0
            //   0f8660010000         | jbe                 0x166

        $sequence_14 = { ff750c ff7508 ff15???????? 8945a8 3bc3 752b }
            // n = 6, score = 200
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   8945a8               | mov                 dword ptr [ebp - 0x58], eax
            //   3bc3                 | cmp                 eax, ebx
            //   752b                 | jne                 0x2d

        $sequence_15 = { 33ff eb06 56 e8???????? }
            // n = 4, score = 200
            //   33ff                 | xor                 edi, edi
            //   eb06                 | jmp                 8
            //   56                   | push                esi
            //   e8????????           |                     

    condition:
        7 of them and filesize < 172032
}