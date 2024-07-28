rule win_neddnloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.neddnloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.neddnloader"
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
        $sequence_0 = { 83c204 3bcf 72f0 8d43ff }
            // n = 4, score = 400
            //   83c204               | add                 edx, 4
            //   3bcf                 | cmp                 ecx, edi
            //   72f0                 | jb                  0xfffffff2
            //   8d43ff               | lea                 eax, [ebx - 1]

        $sequence_1 = { 69c0b179379e c1e813 03c9 0fb73411 }
            // n = 4, score = 400
            //   69c0b179379e         | imul                eax, eax, 0x9e3779b1
            //   c1e813               | shr                 eax, 0x13
            //   03c9                 | add                 ecx, ecx
            //   0fb73411             | movzx               esi, word ptr [ecx + edx]

        $sequence_2 = { 8b5508 69c0b179379e c1e813 33c9 66890c42 }
            // n = 5, score = 400
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   69c0b179379e         | imul                eax, eax, 0x9e3779b1
            //   c1e813               | shr                 eax, 0x13
            //   33c9                 | xor                 ecx, ecx
            //   66890c42             | mov                 word ptr [edx + eax*2], cx

        $sequence_3 = { 8d43ff 3bc8 7311 0fb702 }
            // n = 4, score = 400
            //   8d43ff               | lea                 eax, [ebx - 1]
            //   3bc8                 | cmp                 ecx, eax
            //   7311                 | jae                 0x13
            //   0fb702               | movzx               eax, word ptr [edx]

        $sequence_4 = { 8bc1 2b45fc 5f 5e }
            // n = 4, score = 400
            //   8bc1                 | mov                 eax, ecx
            //   2b45fc               | sub                 eax, dword ptr [ebp - 4]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_5 = { eb02 0008 8b45f8 83c0f4 897dfc }
            // n = 5, score = 400
            //   eb02                 | jmp                 4
            //   0008                 | add                 byte ptr [eax], cl
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   83c0f4               | add                 eax, -0xc
            //   897dfc               | mov                 dword ptr [ebp - 4], edi

        $sequence_6 = { 663bc6 7506 83c102 83c202 3bcb 7307 }
            // n = 6, score = 400
            //   663bc6               | cmp                 ax, si
            //   7506                 | jne                 8
            //   83c102               | add                 ecx, 2
            //   83c202               | add                 edx, 2
            //   3bcb                 | cmp                 ecx, ebx
            //   7307                 | jae                 9

        $sequence_7 = { 7311 0fb702 0fb731 663bc6 7506 83c102 }
            // n = 6, score = 400
            //   7311                 | jae                 0x13
            //   0fb702               | movzx               eax, word ptr [edx]
            //   0fb731               | movzx               esi, word ptr [ecx]
            //   663bc6               | cmp                 ax, si
            //   7506                 | jne                 8
            //   83c102               | add                 ecx, 2

        $sequence_8 = { 488bf2 41c1ed04 492bf0 41ffc5 488bd3 488bcf }
            // n = 6, score = 100
            //   488bf2               | movzx               edx, al
            //   41c1ed04             | dec                 eax
            //   492bf0               | lea                 ecx, [0x11014]
            //   41ffc5               | mov                 edx, 0xfa0
            //   488bd3               | dec                 eax
            //   488bcf               | mov                 eax, ebp

        $sequence_9 = { 410fb6c0 4133b48e803c0100 4133b48680480100 418bc0 41337530 c1e808 0fb6d0 }
            // n = 7, score = 100
            //   410fb6c0             | inc                 ecx
            //   4133b48e803c0100     | mov                 eax, esi
            //   4133b48680480100     | inc                 ebp
            //   418bc0               | mov                 edx, dword ptr [esp + edx*4 + 0x14480]
            //   41337530             | shr                 eax, 0x10
            //   c1e808               | movzx               ecx, al
            //   0fb6d0               | mov                 eax, ebp

        $sequence_10 = { 0fb6c8 410fb6c0 4133bc8e803c0100 4133bc8680480100 41337d60 418bc0 }
            // n = 6, score = 100
            //   0fb6c8               | and                 ebp, 0x1f
            //   410fb6c0             | dec                 eax
            //   4133bc8e803c0100     | sar                 eax, 5
            //   4133bc8680480100     | dec                 eax
            //   41337d60             | imul                ebp, ebp, 0x58
            //   418bc0               | dec                 eax

        $sequence_11 = { 448bce 448bc7 488bd0 498bce e8???????? 448bf0 }
            // n = 6, score = 100
            //   448bce               | inc                 esp
            //   448bc7               | mov                 ecx, esi
            //   488bd0               | inc                 esp
            //   498bce               | mov                 eax, edi
            //   e8????????           |                     
            //   448bf0               | dec                 eax

        $sequence_12 = { 488d3d24570000 eb0e 488b03 4885c0 7402 }
            // n = 5, score = 100
            //   488d3d24570000       | inc                 ecx
            //   eb0e                 | mov                 eax, eax
            //   488b03               | inc                 ecx
            //   4885c0               | xor                 esi, dword ptr [ebp + 0x30]
            //   7402                 | shr                 eax, 8

        $sequence_13 = { 0fb6d0 418bc6 458b949480440100 c1e810 0fb6c8 8bc5 }
            // n = 6, score = 100
            //   0fb6d0               | mov                 edx, eax
            //   418bc6               | dec                 ecx
            //   458b949480440100     | mov                 ecx, esi
            //   c1e810               | inc                 esp
            //   0fb6c8               | mov                 esi, eax
            //   8bc5                 | movzx               edx, al

        $sequence_14 = { 488d0d14100100 baa00f0000 488bc5 83e51f 48c1f805 486bed58 }
            // n = 6, score = 100
            //   488d0d14100100       | inc                 ecx
            //   baa00f0000           | movzx               eax, al
            //   488bc5               | inc                 ecx
            //   83e51f               | xor                 esi, dword ptr [esi + ecx*4 + 0x13c80]
            //   48c1f805             | inc                 ecx
            //   486bed58             | xor                 esi, dword ptr [esi + eax*4 + 0x14880]

        $sequence_15 = { ff5348 b97f000000 ff15???????? eb1e 488b5350 498bcd ff5348 }
            // n = 7, score = 100
            //   ff5348               | lea                 edi, [0x5724]
            //   b97f000000           | jmp                 0x17
            //   ff15????????         |                     
            //   eb1e                 | dec                 eax
            //   488b5350             | mov                 eax, dword ptr [ebx]
            //   498bcd               | dec                 eax
            //   ff5348               | test                eax, eax

    condition:
        7 of them and filesize < 3438592
}