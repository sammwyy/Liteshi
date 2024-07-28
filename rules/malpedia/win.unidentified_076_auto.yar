rule win_unidentified_076_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_076."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_076"
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
        $sequence_0 = { 488b5370 488d4520 488bcb 4889442420 e8???????? 8bc8 eb7c }
            // n = 7, score = 100
            //   488b5370             | call                dword ptr [eax + 0x80]
            //   488d4520             | test                eax, eax
            //   488bcb               | dec                 eax
            //   4889442420           | mov                 ecx, edi
            //   e8????????           |                     
            //   8bc8                 | dec                 eax
            //   eb7c                 | mov                 eax, dword ptr [edi + 0xc8]

        $sequence_1 = { 747b 8d5620 448bce 448bc5 33c9 ff97f8000000 48898748020000 }
            // n = 7, score = 100
            //   747b                 | inc                 esp
            //   8d5620               | cmp                 dword ptr [ebx + 0x40], ecx
            //   448bce               | jne                 0x1b1e
            //   448bc5               | inc                 esp
            //   33c9                 | cmp                 dword ptr [ebx + 0x78], ecx
            //   ff97f8000000         | jl                  0x1a80
            //   48898748020000       | inc                 ebp

        $sequence_2 = { 488bcf ff9080000000 33d2 33c9 4c63c0 85c0 7e29 }
            // n = 7, score = 100
            //   488bcf               | xor                 eax, eax
            //   ff9080000000         | test                ebp, ebp
            //   33d2                 | setle               al
            //   33c9                 | inc                 esp
            //   4c63c0               | cmp                 esp, eax
            //   85c0                 | dec                 ecx
            //   7e29                 | arpl                word ptr [esi], ax

        $sequence_3 = { 48894178 488b8f80000000 488b4618 48034f50 48898880000000 488b8f90000000 488b4618 }
            // n = 7, score = 100
            //   48894178             | mov                 ecx, esi
            //   488b8f80000000       | call                dword ptr [edx + 0x170]
            //   488b4618             | dec                 eax
            //   48034f50             | mov                 ebp, dword ptr [esp + 0x60]
            //   48898880000000       | mov                 eax, ebx
            //   488b8f90000000       | dec                 eax
            //   488b4618             | mov                 ebx, dword ptr [esp + 0x58]

        $sequence_4 = { 458d6502 448bc7 488bce 4489642428 89442420 e8???????? 85c0 }
            // n = 7, score = 100
            //   458d6502             | mov                 esi, dword ptr [esp + 0x48]
            //   448bc7               | mov                 eax, edi
            //   488bce               | dec                 eax
            //   4489642428           | add                 esp, 0x30
            //   89442420             | pop                 edi
            //   e8????????           |                     
            //   85c0                 | ret                 

        $sequence_5 = { 488d8d40150000 e8???????? 488d1587720000 488d8d14090000 8985d4000000 488d05c3130000 c7853001000000080000 }
            // n = 7, score = 100
            //   488d8d40150000       | jmp                 0x18d6
            //   e8????????           |                     
            //   488d1587720000       | dec                 ecx
            //   488d8d14090000       | mov                 ecx, dword ptr [eax]
            //   8985d4000000         | dec                 ecx
            //   488d05c3130000       | mov                 eax, dword ptr [eax + 8]
            //   c7853001000000080000     | dec    ecx

        $sequence_6 = { 4533c9 488bcf 448d420c 48895c2420 e8???????? eb05 bb01000000 }
            // n = 7, score = 100
            //   4533c9               | dec                 eax
            //   488bcf               | mov                 eax, dword ptr [esp + 0x30]
            //   448d420c             | dec                 eax
            //   48895c2420           | lea                 ecx, [edi + 0x5bc]
            //   e8????????           |                     
            //   eb05                 | dec                 eax
            //   bb01000000           | mov                 dword ptr [esp + 0xa0], eax

        $sequence_7 = { 7f0b 41b907000000 e9???????? 488b83c8000000 488b9360020000 488d8b5c060000 ff90f0070000 }
            // n = 7, score = 100
            //   7f0b                 | je                  0x12f6
            //   41b907000000         | sub                 ecx, 0xa
            //   e9????????           |                     
            //   488b83c8000000       | sub                 ecx, 0xa
            //   488b9360020000       | je                  0x12ca
            //   488d8b5c060000       | cmp                 ecx, 0x14
            //   ff90f0070000         | je                  0x12ab

        $sequence_8 = { 89442420 e8???????? eb56 83f801 7529 8b8714120000 448b8f10120000 }
            // n = 7, score = 100
            //   89442420             | mov                 dword ptr [ebx + 0x290], eax
            //   e8????????           |                     
            //   eb56                 | dec                 eax
            //   83f801               | test                eax, eax
            //   7529                 | dec                 eax
            //   8b8714120000         | mov                 eax, dword ptr [ebx + 0xc8]
            //   448b8f10120000       | mov                 dword ptr [esp + 0x20], edi

        $sequence_9 = { 415e 415c c3 817d0c08020000 7c05 458bcc eba2 }
            // n = 7, score = 100
            //   415e                 | xor                 byte ptr [edx], al
            //   415c                 | dec                 eax
            //   c3                   | inc                 edx
            //   817d0c08020000       | dec                 ecx
            //   7c05                 | dec                 eax
            //   458bcc               | dec                 eax
            //   eba2                 | cmovge              ecx, esi

    condition:
        7 of them and filesize < 114688
}