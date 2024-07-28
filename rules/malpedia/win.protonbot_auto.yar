rule win_protonbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.protonbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.protonbot"
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
        $sequence_0 = { 0f434550 6a00 6a00 6a00 }
            // n = 4, score = 400
            //   0f434550             | cmovae              eax, dword ptr [ebp + 0x50]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_1 = { 8b36 8d442408 50 56 e8???????? 83c408 83f808 }
            // n = 7, score = 400
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   8d442408             | lea                 eax, [esp + 8]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   83f808               | cmp                 eax, 8

        $sequence_2 = { e8???????? 8d8dd4feffff e8???????? 83c418 c645fc01 }
            // n = 5, score = 400
            //   e8????????           |                     
            //   8d8dd4feffff         | lea                 ecx, [ebp - 0x12c]
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1

        $sequence_3 = { 899df8fffeff e8???????? 83c410 8bf8 }
            // n = 4, score = 400
            //   899df8fffeff         | mov                 dword ptr [ebp - 0x10008], ebx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8bf8                 | mov                 edi, eax

        $sequence_4 = { 8bf1 6a04 c745fc01000000 e8???????? 83c404 8bf8 }
            // n = 6, score = 400
            //   8bf1                 | mov                 esi, ecx
            //   6a04                 | push                4
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bf8                 | mov                 edi, eax

        $sequence_5 = { 837f1410 7202 8b3f 57 50 e8???????? ffb5d4feffff }
            // n = 7, score = 400
            //   837f1410             | cmp                 dword ptr [edi + 0x14], 0x10
            //   7202                 | jb                  4
            //   8b3f                 | mov                 edi, dword ptr [edi]
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   ffb5d4feffff         | push                dword ptr [ebp - 0x12c]

        $sequence_6 = { 7f8d 5e 5f 33c0 5b 8b4dfc }
            // n = 6, score = 400
            //   7f8d                 | jg                  0xffffff8f
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_7 = { 50 8d45f4 64a300000000 8bda 8bf9 8d8dd8feffff }
            // n = 6, score = 400
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bda                 | mov                 ebx, edx
            //   8bf9                 | mov                 edi, ecx
            //   8d8dd8feffff         | lea                 ecx, [ebp - 0x128]

        $sequence_8 = { 8d85b8fbffff 0f4385b8fbffff 50 8d85d0fbffff 68ff000000 50 e8???????? }
            // n = 7, score = 400
            //   8d85b8fbffff         | lea                 eax, [ebp - 0x448]
            //   0f4385b8fbffff       | cmovae              eax, dword ptr [ebp - 0x448]
            //   50                   | push                eax
            //   8d85d0fbffff         | lea                 eax, [ebp - 0x430]
            //   68ff000000           | push                0xff
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_9 = { b901000000 8bc2 c1e81e 33c2 69d06589076c 03d1 89948d54ecffff }
            // n = 7, score = 400
            //   b901000000           | mov                 ecx, 1
            //   8bc2                 | mov                 eax, edx
            //   c1e81e               | shr                 eax, 0x1e
            //   33c2                 | xor                 eax, edx
            //   69d06589076c         | imul                edx, eax, 0x6c078965
            //   03d1                 | add                 edx, ecx
            //   89948d54ecffff       | mov                 dword ptr [ebp + ecx*4 - 0x13ac], edx

    condition:
        7 of them and filesize < 1073152
}