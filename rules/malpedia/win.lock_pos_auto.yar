rule win_lock_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lock_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lock_pos"
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
        $sequence_0 = { 8bec 8b4508 8b0d???????? 8b0481 }
            // n = 4, score = 400
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b0d????????         |                     
            //   8b0481               | mov                 eax, dword ptr [ecx + eax*4]

        $sequence_1 = { 55 8bec 837d0800 7704 }
            // n = 4, score = 400
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7704                 | ja                  6

        $sequence_2 = { 55 8bec 81eca4040000 56 }
            // n = 4, score = 300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81eca4040000         | sub                 esp, 0x4a4
            //   56                   | push                esi

        $sequence_3 = { 8d85f8fdffff 50 6a00 6a00 6a23 6a00 ff15???????? }
            // n = 7, score = 300
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a23                 | push                0x23
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_4 = { 0fb64dfb 85c9 741c 8b5514 8b45fc }
            // n = 5, score = 200
            //   0fb64dfb             | movzx               ecx, byte ptr [ebp - 5]
            //   85c9                 | test                ecx, ecx
            //   741c                 | je                  0x1e
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_5 = { 2bc8 c745fc04000000 8a1401 8810 40 }
            // n = 5, score = 200
            //   2bc8                 | sub                 ecx, eax
            //   c745fc04000000       | mov                 dword ptr [ebp - 4], 4
            //   8a1401               | mov                 dl, byte ptr [ecx + eax]
            //   8810                 | mov                 byte ptr [eax], dl
            //   40                   | inc                 eax

        $sequence_6 = { 8b55f8 8b4508 8910 8b45c4 }
            // n = 4, score = 200
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]

        $sequence_7 = { 3bc6 0f85a1000000 32db e8???????? 84db }
            // n = 5, score = 200
            //   3bc6                 | cmp                 eax, esi
            //   0f85a1000000         | jne                 0xa7
            //   32db                 | xor                 bl, bl
            //   e8????????           |                     
            //   84db                 | test                bl, bl

        $sequence_8 = { 8b55fc 8b450c 0fb70c50 334d14 }
            // n = 4, score = 200
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fb70c50             | movzx               ecx, word ptr [eax + edx*2]
            //   334d14               | xor                 ecx, dword ptr [ebp + 0x14]

        $sequence_9 = { 33c9 84c0 0f95c1 41 51 ff75e4 }
            // n = 6, score = 200
            //   33c9                 | xor                 ecx, ecx
            //   84c0                 | test                al, al
            //   0f95c1               | setne               cl
            //   41                   | inc                 ecx
            //   51                   | push                ecx
            //   ff75e4               | push                dword ptr [ebp - 0x1c]

        $sequence_10 = { 894dfc 8b55dc 83c201 8955dc ebd2 8b45f8 }
            // n = 6, score = 200
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   83c201               | add                 edx, 1
            //   8955dc               | mov                 dword ptr [ebp - 0x24], edx
            //   ebd2                 | jmp                 0xffffffd4
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_11 = { e8???????? 83c408 8d9568ffffff 52 e8???????? 83c404 50 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d9568ffffff         | lea                 edx, [ebp - 0x98]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   50                   | push                eax

        $sequence_12 = { 50 eb4b 8b45f8 3bc3 764e 03c7 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   eb4b                 | jmp                 0x4d
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   3bc3                 | cmp                 eax, ebx
            //   764e                 | jbe                 0x50
            //   03c7                 | add                 eax, edi

    condition:
        7 of them and filesize < 319488
}