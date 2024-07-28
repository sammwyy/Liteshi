rule win_mechanical_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.mechanical."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mechanical"
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
        $sequence_0 = { 03c7 3bca 72ed 5f }
            // n = 4, score = 200
            //   03c7                 | mov                 al, byte ptr [ebx]
            //   3bca                 | add                 esi, dword ptr [eax*4 + 0x42e5c0]
            //   72ed                 | mov                 eax, dword ptr [ebp - 0x1c]
            //   5f                   | mov                 eax, dword ptr [eax]

        $sequence_1 = { c6025e eb12 c6022f eb0d }
            // n = 4, score = 200
            //   c6025e               | dec                 eax
            //   eb12                 | movsx               eax, ch
            //   c6022f               | inc                 edx
            //   eb0d                 | mov                 cl, byte ptr [eax + edx + 0x27c50]

        $sequence_2 = { 8b442430 488d8c2471110000 33d2 41b803010000 }
            // n = 4, score = 200
            //   8b442430             | dec                 esp
            //   488d8c2471110000     | lea                 ebx, [0x1d45c]
            //   33d2                 | dec                 ecx
            //   41b803010000         | mov                 ecx, esp

        $sequence_3 = { 0401 3cbe 8844240b 76e2 }
            // n = 4, score = 200
            //   0401                 | cmp                 dword ptr [esi + 8], ebx
            //   3cbe                 | jne                 0x44
            //   8844240b             | push                0xa
            //   76e2                 | add                 esi, dword ptr [eax*4 + 0x42e5c0]

        $sequence_4 = { 03ce c6840c3801000000 8d8424a05c0000 33f6 }
            // n = 4, score = 200
            //   03ce                 | mov                 dword ptr [esi], eax
            //   c6840c3801000000     | mov                 al, byte ptr [ebx]
            //   8d8424a05c0000       | mov                 byte ptr [esi + 4], al
            //   33f6                 | add                 esi, dword ptr [eax*4 + 0x42e5c0]

        $sequence_5 = { 033485c0e54200 c745e401000000 33db 395e08 }
            // n = 4, score = 200
            //   033485c0e54200       | je                  0x1c
            //   c745e401000000       | push                2
            //   33db                 | push                ebx
            //   395e08               | add                 eax, dword ptr [edx*4 + 0x42e5c0]

        $sequence_6 = { 488d15d9d20000 488bcb e8???????? 85c0 750a 4883c310 }
            // n = 6, score = 200
            //   488d15d9d20000       | mov                 byte ptr [edx], 0x5f
            //   488bcb               | jmp                 0x5a
            //   e8????????           |                     
            //   85c0                 | mov                 byte ptr [edx], 0x3a
            //   750a                 | inc                 esp
            //   4883c310             | mov                 byte ptr [esp + 0xd30], ah

        $sequence_7 = { 00686c 42 0023 d18a0688078a }
            // n = 4, score = 200
            //   00686c               | jmp                 0x62
            //   42                   | mov                 byte ptr [edx], 0x5f
            //   0023                 | jmp                 0x62
            //   d18a0688078a         | mov                 byte ptr [edx], 0x3a

        $sequence_8 = { 4488a424300d0000 488905???????? e8???????? 4c8d1d5cd40100 498bcc }
            // n = 5, score = 200
            //   4488a424300d0000     | jmp                 0x69
            //   488905????????       |                     
            //   e8????????           |                     
            //   4c8d1d5cd40100       | mov                 byte ptr [edx], 0x3d
            //   498bcc               | jmp                 0x69

        $sequence_9 = { eb62 c6023d eb5d c6025f eb58 c6023a }
            // n = 6, score = 200
            //   eb62                 | and                 ecx, 0xf
            //   c6023d               | jmp                 0x14
            //   eb5d                 | mov                 byte ptr [edx], 0x5e
            //   c6025f               | jmp                 0x17
            //   eb58                 | mov                 byte ptr [edx], 0x2f
            //   c6023a               | jmp                 0x12

        $sequence_10 = { 03c1 1bc9 0bc1 59 e9???????? e8???????? ff742404 }
            // n = 7, score = 200
            //   03c1                 | mov                 dword ptr [esi], eax
            //   1bc9                 | add                 esi, dword ptr [eax*4 + 0x42e5c0]
            //   0bc1                 | mov                 eax, dword ptr [ebp - 0x1c]
            //   59                   | mov                 eax, dword ptr [eax]
            //   e9????????           |                     
            //   e8????????           |                     
            //   ff742404             | mov                 dword ptr [esi], eax

        $sequence_11 = { 41c1c90d 8bca 4983c201 4403c8 493bc8 }
            // n = 5, score = 200
            //   41c1c90d             | inc                 ecx
            //   8bca                 | ror                 ecx, 0xd
            //   4983c201             | mov                 ecx, edx
            //   4403c8               | dec                 ecx
            //   493bc8               | add                 edx, 1

        $sequence_12 = { 033485c0e54200 8b45e4 8b00 8906 }
            // n = 4, score = 200
            //   033485c0e54200       | inc                 esi
            //   8b45e4               | add                 byte ptr [eax + 0x6c], ch
            //   8b00                 | inc                 edx
            //   8906                 | add                 byte ptr [ebx], ah

        $sequence_13 = { 030495c0e54200 eb05 b8???????? f6400420 }
            // n = 4, score = 200
            //   030495c0e54200       | jne                 0x11
            //   eb05                 | dec                 eax
            //   b8????????           |                     
            //   f6400420             | add                 ebx, 0x10

        $sequence_14 = { 33d2 41b803010000 4488a42470110000 488905???????? e8???????? }
            // n = 5, score = 200
            //   33d2                 | dec                 eax
            //   41b803010000         | lea                 edx, [0xd2d9]
            //   4488a42470110000     | dec                 eax
            //   488905????????       |                     
            //   e8????????           |                     

        $sequence_15 = { 3c58 7711 480fbec5 428a8c10507c0200 83e10f eb03 }
            // n = 6, score = 200
            //   3c58                 | inc                 esp
            //   7711                 | add                 ecx, eax
            //   480fbec5             | dec                 ecx
            //   428a8c10507c0200     | cmp                 ecx, eax
            //   83e10f               | cmp                 al, 0x58
            //   eb03                 | ja                  0x15

    condition:
        7 of them and filesize < 434176
}