rule win_graphite_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.graphite."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.graphite"
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
        $sequence_0 = { 7513 33d2 e8???????? 84c0 }
            // n = 4, score = 500
            //   7513                 | mov                 byte ptr [ebx], cl
            //   33d2                 | mov                 ecx, dword ptr [ebp + 0x48]
            //   e8????????           |                     
            //   84c0                 | shr                 ecx, 6

        $sequence_1 = { 33d2 e8???????? 84c0 74e4 }
            // n = 4, score = 500
            //   33d2                 | sub                 ebx, dword ptr [ebp + 0x20]
            //   e8????????           |                     
            //   84c0                 | dec                 eax
            //   74e4                 | mov                 edx, edi

        $sequence_2 = { 81e2ff030000 81e1bf030000 83c940 c1e10a }
            // n = 4, score = 500
            //   81e2ff030000         | mov                 ecx, dword ptr [ebx + 4]
            //   81e1bf030000         | lea                 eax, [esp + 0x38]
            //   83c940               | push                esi
            //   c1e10a               | lea                 esi, [edi + eax*2]

        $sequence_3 = { 7513 33d2 e8???????? 84c0 74e4 }
            // n = 5, score = 500
            //   7513                 | lea                 eax, [ebp + 0x58]
            //   33d2                 | dec                 eax
            //   e8????????           |                     
            //   84c0                 | lea                 edx, [ebp + 0x50]
            //   74e4                 | dec                 eax

        $sequence_4 = { 81e1bf030000 83c940 c1e10a 0bca }
            // n = 4, score = 500
            //   81e1bf030000         | push                esi
            //   83c940               | mov                 dword ptr [esp + 0x20], eax
            //   c1e10a               | inc                 eax
            //   0bca                 | push                esi

        $sequence_5 = { ff15???????? 33c0 eb05 b801010000 }
            // n = 4, score = 500
            //   ff15????????         |                     
            //   33c0                 | mov                 dword ptr [ebp - 0x50], 0x5736571a
            //   eb05                 | mov                 dword ptr [ebp - 0x5c], 0x98ae859f
            //   b801010000           | mov                 dword ptr [ebp - 0x58], 0x82d4cc95

        $sequence_6 = { 85db 7513 33d2 e8???????? 84c0 74e4 }
            // n = 6, score = 500
            //   85db                 | mov                 ebx, eax
            //   7513                 | dec                 eax
            //   33d2                 | test                eax, eax
            //   e8????????           |                     
            //   84c0                 | je                  0xf36
            //   74e4                 | dec                 eax

        $sequence_7 = { 85db 7513 33d2 e8???????? 84c0 }
            // n = 5, score = 500
            //   85db                 | push                ebx
            //   7513                 | push                dword ptr [esp + 0x1c]
            //   33d2                 | push                esi
            //   e8????????           |                     
            //   84c0                 | call                edi

        $sequence_8 = { 85db 7513 33d2 e8???????? }
            // n = 4, score = 500
            //   85db                 | push                0x17
            //   7513                 | mov                 word ptr [ebp - 4], 0xb5d9
            //   33d2                 | push                0x31
            //   e8????????           |                     

        $sequence_9 = { 81e2ff030000 81e1bf030000 83c940 c1e10a 0bca }
            // n = 5, score = 500
            //   81e2ff030000         | add                 ebp, 0x14
            //   81e1bf030000         | dec                 ebp
            //   83c940               | mov                 ebp, ecx
            //   c1e10a               | dec                 ebp
            //   0bca                 | mov                 esi, eax

    condition:
        7 of them and filesize < 98304
}