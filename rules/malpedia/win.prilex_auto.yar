rule win_prilex_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.prilex."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prilex"
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
        $sequence_0 = { 8be8 ffd7 8d442410 8d4c2414 }
            // n = 4, score = 400
            //   8be8                 | mov                 ebp, eax
            //   ffd7                 | call                edi
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

        $sequence_1 = { 8b0f 51 ff15???????? 8945e4 68???????? }
            // n = 5, score = 400
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   68????????           |                     

        $sequence_2 = { 8d442424 6a0c 8b11 50 52 56 }
            // n = 6, score = 400
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   6a0c                 | push                0xc
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   50                   | push                eax
            //   52                   | push                edx
            //   56                   | push                esi

        $sequence_3 = { e8???????? 5d 8d4c2420 8d542414 51 }
            // n = 5, score = 400
            //   e8????????           |                     
            //   5d                   | pop                 ebp
            //   8d4c2420             | lea                 ecx, [esp + 0x20]
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   51                   | push                ecx

        $sequence_4 = { ff15???????? c745fc02000000 8b4510 33c9 833800 0f95c1 }
            // n = 6, score = 400
            //   ff15????????         |                     
            //   c745fc02000000       | mov                 dword ptr [ebp - 4], 2
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   33c9                 | xor                 ecx, ecx
            //   833800               | cmp                 dword ptr [eax], 0
            //   0f95c1               | setne               cl

        $sequence_5 = { 8d858cfdffff 52 8d8d9cfdffff 50 51 }
            // n = 5, score = 400
            //   8d858cfdffff         | lea                 eax, [ebp - 0x274]
            //   52                   | push                edx
            //   8d8d9cfdffff         | lea                 ecx, [ebp - 0x264]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_6 = { 83c104 898d24ffffff c7851cffffff03400000 8d951cffffff 52 8d458c 50 }
            // n = 7, score = 400
            //   83c104               | add                 ecx, 4
            //   898d24ffffff         | mov                 dword ptr [ebp - 0xdc], ecx
            //   c7851cffffff03400000     | mov    dword ptr [ebp - 0xe4], 0x4003
            //   8d951cffffff         | lea                 edx, [ebp - 0xe4]
            //   52                   | push                edx
            //   8d458c               | lea                 eax, [ebp - 0x74]
            //   50                   | push                eax

        $sequence_7 = { 8d8dacfdffff 68???????? 52 898d54fdffff c7854cfdffff08400000 }
            // n = 5, score = 400
            //   8d8dacfdffff         | lea                 ecx, [ebp - 0x254]
            //   68????????           |                     
            //   52                   | push                edx
            //   898d54fdffff         | mov                 dword ptr [ebp - 0x2ac], ecx
            //   c7854cfdffff08400000     | mov    dword ptr [ebp - 0x2b4], 0x4008

        $sequence_8 = { e8???????? 8bf0 ff15???????? 8d45ac }
            // n = 4, score = 400
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   8d45ac               | lea                 eax, [ebp - 0x54]

        $sequence_9 = { ffd6 50 8d4da0 68???????? 51 ffd6 }
            // n = 6, score = 400
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   8d4da0               | lea                 ecx, [ebp - 0x60]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ffd6                 | call                esi

    condition:
        7 of them and filesize < 450560
}