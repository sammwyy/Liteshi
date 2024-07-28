rule win_glassrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.glassrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glassrat"
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
        $sequence_0 = { 8d542438 83c9ff 33c0 f2ae f7d1 2bf9 8bc1 }
            // n = 7, score = 200
            //   8d542438             | lea                 edx, [esp + 0x38]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   8bc1                 | mov                 eax, ecx

        $sequence_1 = { ff15???????? 33c0 8b5504 8944241d 8d4c241c }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   8b5504               | mov                 edx, dword ptr [ebp + 4]
            //   8944241d             | mov                 dword ptr [esp + 0x1d], eax
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]

        $sequence_2 = { 747a 3bfe 7476 56 56 56 53 }
            // n = 7, score = 200
            //   747a                 | je                  0x7c
            //   3bfe                 | cmp                 edi, esi
            //   7476                 | je                  0x78
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi
            //   53                   | push                ebx

        $sequence_3 = { 895db8 895dbc ff15???????? 85c0 0f84bb000000 }
            // n = 5, score = 200
            //   895db8               | mov                 dword ptr [ebp - 0x48], ebx
            //   895dbc               | mov                 dword ptr [ebp - 0x44], ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84bb000000         | je                  0xc1

        $sequence_4 = { 3bc8 b802000000 0f85b4000000 33d2 b909020000 52 83ec10 }
            // n = 7, score = 200
            //   3bc8                 | cmp                 ecx, eax
            //   b802000000           | mov                 eax, 2
            //   0f85b4000000         | jne                 0xba
            //   33d2                 | xor                 edx, edx
            //   b909020000           | mov                 ecx, 0x209
            //   52                   | push                edx
            //   83ec10               | sub                 esp, 0x10

        $sequence_5 = { 6a04 51 52 8844243b }
            // n = 4, score = 200
            //   6a04                 | push                4
            //   51                   | push                ecx
            //   52                   | push                edx
            //   8844243b             | mov                 byte ptr [esp + 0x3b], al

        $sequence_6 = { 8b460c 53 53 57 50 }
            // n = 5, score = 200
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   57                   | push                edi
            //   50                   | push                eax

        $sequence_7 = { 8bce ff12 57 ff15???????? 8d4c2420 }
            // n = 5, score = 200
            //   8bce                 | mov                 ecx, esi
            //   ff12                 | call                dword ptr [edx]
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8d4c2420             | lea                 ecx, [esp + 0x20]

        $sequence_8 = { 89442418 ff15???????? 8b4d04 8b1d???????? }
            // n = 4, score = 200
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   ff15????????         |                     
            //   8b4d04               | mov                 ecx, dword ptr [ebp + 4]
            //   8b1d????????         |                     

        $sequence_9 = { 89442408 89542404 8a15???????? 33c0 }
            // n = 4, score = 200
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   89542404             | mov                 dword ptr [esp + 4], edx
            //   8a15????????         |                     
            //   33c0                 | xor                 eax, eax

    condition:
        7 of them and filesize < 81920
}