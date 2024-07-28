rule win_atmitch_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.atmitch."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atmitch"
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
        $sequence_0 = { c644244803 ff15???????? 8d4c2418 51 68???????? }
            // n = 5, score = 100
            //   c644244803           | mov                 byte ptr [esp + 0x48], 3
            //   ff15????????         |                     
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   51                   | push                ecx
            //   68????????           |                     

        $sequence_1 = { 33c4 89842410020000 56 51 8bcc }
            // n = 5, score = 100
            //   33c4                 | xor                 eax, esp
            //   89842410020000       | mov                 dword ptr [esp + 0x210], eax
            //   56                   | push                esi
            //   51                   | push                ecx
            //   8bcc                 | mov                 ecx, esp

        $sequence_2 = { 8bfe f7df 896c241c 0fb744242c 50 51 }
            // n = 6, score = 100
            //   8bfe                 | mov                 edi, esi
            //   f7df                 | neg                 edi
            //   896c241c             | mov                 dword ptr [esp + 0x1c], ebp
            //   0fb744242c           | movzx               eax, word ptr [esp + 0x2c]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_3 = { 51 833d????????00 7422 a1???????? 50 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   833d????????00       |                     
            //   7422                 | je                  0x24
            //   a1????????           |                     
            //   50                   | push                eax

        $sequence_4 = { ff15???????? e8???????? 8b0e 8b5138 83c408 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   e8????????           |                     
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   8b5138               | mov                 edx, dword ptr [ecx + 0x38]
            //   83c408               | add                 esp, 8

        $sequence_5 = { c744241c00000000 b8???????? c60000 83c004 3d???????? 7cf3 68???????? }
            // n = 7, score = 100
            //   c744241c00000000     | mov                 dword ptr [esp + 0x1c], 0
            //   b8????????           |                     
            //   c60000               | mov                 byte ptr [eax], 0
            //   83c004               | add                 eax, 4
            //   3d????????           |                     
            //   7cf3                 | jl                  0xfffffff5
            //   68????????           |                     

        $sequence_6 = { 8bcc 89642410 68???????? ff15???????? e8???????? 0fb705???????? 83c408 }
            // n = 7, score = 100
            //   8bcc                 | mov                 ecx, esp
            //   89642410             | mov                 dword ptr [esp + 0x10], esp
            //   68????????           |                     
            //   ff15????????         |                     
            //   e8????????           |                     
            //   0fb705????????       |                     
            //   83c408               | add                 esp, 8

        $sequence_7 = { ff15???????? 83bc24fc00000000 7432 8b4c2408 8b41f4 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   83bc24fc00000000     | cmp                 dword ptr [esp + 0xfc], 0
            //   7432                 | je                  0x34
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   8b41f4               | mov                 eax, dword ptr [ecx - 0xc]

        $sequence_8 = { c644244803 ff15???????? 8d4c2418 51 68???????? 8d542428 52 }
            // n = 7, score = 100
            //   c644244803           | mov                 byte ptr [esp + 0x48], 3
            //   ff15????????         |                     
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   51                   | push                ecx
            //   68????????           |                     
            //   8d542428             | lea                 edx, [esp + 0x28]
            //   52                   | push                edx

        $sequence_9 = { 83c404 50 ff15???????? 50 51 }
            // n = 5, score = 100
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   50                   | push                eax
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 73728
}