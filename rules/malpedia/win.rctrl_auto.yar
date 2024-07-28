rule win_rctrl_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rctrl."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rctrl"
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
        $sequence_0 = { e8???????? 85c0 0f8440030000 8b10 8bc8 ff520c 83c010 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8440030000         | je                  0x346
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8bc8                 | mov                 ecx, eax
            //   ff520c               | call                dword ptr [edx + 0xc]
            //   83c010               | add                 eax, 0x10

        $sequence_1 = { 8bf0 56 6a00 6a00 ff15???????? 33c9 894508 }
            // n = 7, score = 100
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   33c9                 | xor                 ecx, ecx
            //   894508               | mov                 dword ptr [ebp + 8], eax

        $sequence_2 = { 6a06 e8???????? cc b8???????? c3 55 8bec }
            // n = 7, score = 100
            //   6a06                 | push                6
            //   e8????????           |                     
            //   cc                   | int3                
            //   b8????????           |                     
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_3 = { 8b473c 8985d4feffff e8???????? 85c0 0f85ef000000 814f2400000400 8b85d8feffff }
            // n = 7, score = 100
            //   8b473c               | mov                 eax, dword ptr [edi + 0x3c]
            //   8985d4feffff         | mov                 dword ptr [ebp - 0x12c], eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f85ef000000         | jne                 0xf5
            //   814f2400000400       | or                  dword ptr [edi + 0x24], 0x40000
            //   8b85d8feffff         | mov                 eax, dword ptr [ebp - 0x128]

        $sequence_4 = { 33c0 40 8be5 5d c20800 6a14 b8???????? }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   6a14                 | push                0x14
            //   b8????????           |                     

        $sequence_5 = { 898368040000 03c8 83bd7cffffff00 7433 8b855cffffff 8db328040000 03c1 }
            // n = 7, score = 100
            //   898368040000         | mov                 dword ptr [ebx + 0x468], eax
            //   03c8                 | add                 ecx, eax
            //   83bd7cffffff00       | cmp                 dword ptr [ebp - 0x84], 0
            //   7433                 | je                  0x35
            //   8b855cffffff         | mov                 eax, dword ptr [ebp - 0xa4]
            //   8db328040000         | lea                 esi, [ebx + 0x428]
            //   03c1                 | add                 eax, ecx

        $sequence_6 = { 75cc 8d4dc8 e8???????? e9???????? e8???????? ffb6f8000000 e8???????? }
            // n = 7, score = 100
            //   75cc                 | jne                 0xffffffce
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   e8????????           |                     
            //   e9????????           |                     
            //   e8????????           |                     
            //   ffb6f8000000         | push                dword ptr [esi + 0xf8]
            //   e8????????           |                     

        $sequence_7 = { ff750c 8bd6 e8???????? 8b4518 8d0c3e 8d1400 }
            // n = 6, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8bd6                 | mov                 edx, esi
            //   e8????????           |                     
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   8d0c3e               | lea                 ecx, [esi + edi]
            //   8d1400               | lea                 edx, [eax + eax]

        $sequence_8 = { 85c0 0f94c0 84c0 7423 6a00 6a00 57 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   0f94c0               | sete                al
            //   84c0                 | test                al, al
            //   7423                 | je                  0x25
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   57                   | push                edi

        $sequence_9 = { ff7008 ff75f0 e8???????? 8bf0 eb02 }
            // n = 5, score = 100
            //   ff7008               | push                dword ptr [eax + 8]
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   eb02                 | jmp                 4

    condition:
        7 of them and filesize < 4315136
}