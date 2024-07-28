rule win_hyperssl_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.hyperssl."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hyperssl"
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
        $sequence_0 = { 0108 3310 c1c607 c1c210 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   3310                 | xor                 edx, dword ptr [eax]
            //   c1c607               | rol                 esi, 7
            //   c1c210               | rol                 edx, 0x10

        $sequence_1 = { 33c3 8b5c244c c1ee12 0bfe 33cf 8bf2 }
            // n = 6, score = 200
            //   33c3                 | xor                 eax, ebx
            //   8b5c244c             | mov                 ebx, dword ptr [esp + 0x4c]
            //   c1ee12               | shr                 esi, 0x12
            //   0bfe                 | or                  edi, esi
            //   33cf                 | xor                 ecx, edi
            //   8bf2                 | mov                 esi, edx

        $sequence_2 = { 0105???????? 8d8d5cffffff 89855cffffff 898560ffffff }
            // n = 4, score = 200
            //   0105????????         |                     
            //   8d8d5cffffff         | lea                 ecx, [ebp - 0xa4]
            //   89855cffffff         | mov                 dword ptr [ebp - 0xa4], eax
            //   898560ffffff         | mov                 dword ptr [ebp - 0xa0], eax

        $sequence_3 = { 2bf0 5f 8a10 301401 8a10 301406 40 }
            // n = 7, score = 200
            //   2bf0                 | sub                 esi, eax
            //   5f                   | pop                 edi
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   301401               | xor                 byte ptr [ecx + eax], dl
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   301406               | xor                 byte ptr [esi + eax], dl
            //   40                   | inc                 eax

        $sequence_4 = { 40 4f 75f2 5f 5e e9???????? c3 }
            // n = 7, score = 200
            //   40                   | inc                 eax
            //   4f                   | dec                 edi
            //   75f2                 | jne                 0xfffffff4
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   e9????????           |                     
            //   c3                   | ret                 

        $sequence_5 = { 7436 8b413c 03c1 742a }
            // n = 4, score = 200
            //   7436                 | je                  0x38
            //   8b413c               | mov                 eax, dword ptr [ecx + 0x3c]
            //   03c1                 | add                 eax, ecx
            //   742a                 | je                  0x2c

        $sequence_6 = { 03c1 742a 8b4028 03c1 }
            // n = 4, score = 200
            //   03c1                 | add                 eax, ecx
            //   742a                 | je                  0x2c
            //   8b4028               | mov                 eax, dword ptr [eax + 0x28]
            //   03c1                 | add                 eax, ecx

        $sequence_7 = { 0101 0100 0100 0100 }
            // n = 4, score = 200
            //   0101                 | add                 dword ptr [ecx], eax
            //   0100                 | add                 dword ptr [eax], eax
            //   0100                 | add                 dword ptr [eax], eax
            //   0100                 | add                 dword ptr [eax], eax

        $sequence_8 = { 0100 0200 0200 0002 0002 }
            // n = 5, score = 200
            //   0100                 | add                 dword ptr [eax], eax
            //   0200                 | add                 al, byte ptr [eax]
            //   0200                 | add                 al, byte ptr [eax]
            //   0002                 | add                 byte ptr [edx], al
            //   0002                 | add                 byte ptr [edx], al

        $sequence_9 = { 33c0 40 5d c20c00 6a08 }
            // n = 5, score = 200
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   6a08                 | push                8

        $sequence_10 = { 0108 3908 1bc9 f7d9 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   3908                 | cmp                 dword ptr [eax], ecx
            //   1bc9                 | sbb                 ecx, ecx
            //   f7d9                 | neg                 ecx

        $sequence_11 = { 8b4028 03c1 7423 56 57 }
            // n = 5, score = 200
            //   8b4028               | mov                 eax, dword ptr [eax + 0x28]
            //   03c1                 | add                 eax, ecx
            //   7423                 | je                  0x25
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_12 = { ff15???????? 8bc8 85c9 7436 8b413c }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   8bc8                 | mov                 ecx, eax
            //   85c9                 | test                ecx, ecx
            //   7436                 | je                  0x38
            //   8b413c               | mov                 eax, dword ptr [ecx + 0x3c]

        $sequence_13 = { 0105???????? 8d558c 89458c 894590 }
            // n = 4, score = 200
            //   0105????????         |                     
            //   8d558c               | lea                 edx, [ebp - 0x74]
            //   89458c               | mov                 dword ptr [ebp - 0x74], eax
            //   894590               | mov                 dword ptr [ebp - 0x70], eax

        $sequence_14 = { c20c00 6a08 68???????? e8???????? 8b450c 83f801 }
            // n = 6, score = 200
            //   c20c00               | ret                 0xc
            //   6a08                 | push                8
            //   68????????           |                     
            //   e8????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   83f801               | cmp                 eax, 1

        $sequence_15 = { 0101 014514 2bf3 8b5d0c }
            // n = 4, score = 200
            //   0101                 | add                 dword ptr [ecx], eax
            //   014514               | add                 dword ptr [ebp + 0x14], eax
            //   2bf3                 | sub                 esi, ebx
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]

        $sequence_16 = { 01442428 8b442428 884500 45 }
            // n = 4, score = 100
            //   01442428             | add                 dword ptr [esp + 0x28], eax
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   884500               | mov                 byte ptr [ebp], al
            //   45                   | inc                 ebp

        $sequence_17 = { 017e0c 5f 8bc6 5e c20800 }
            // n = 5, score = 100
            //   017e0c               | add                 dword ptr [esi + 0xc], edi
            //   5f                   | pop                 edi
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c20800               | ret                 8

        $sequence_18 = { 017e0c 395e10 740f ff7610 }
            // n = 4, score = 100
            //   017e0c               | add                 dword ptr [esi + 0xc], edi
            //   395e10               | cmp                 dword ptr [esi + 0x10], ebx
            //   740f                 | je                  0x11
            //   ff7610               | push                dword ptr [esi + 0x10]

        $sequence_19 = { 017e08 8bc3 e8???????? c20400 }
            // n = 4, score = 100
            //   017e08               | add                 dword ptr [esi + 8], edi
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   c20400               | ret                 4

        $sequence_20 = { 017e0c 8d4d08 e8???????? 5f }
            // n = 4, score = 100
            //   017e0c               | add                 dword ptr [esi + 0xc], edi
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   e8????????           |                     
            //   5f                   | pop                 edi

        $sequence_21 = { 011d???????? 5f 8935???????? 5e }
            // n = 4, score = 100
            //   011d????????         |                     
            //   5f                   | pop                 edi
            //   8935????????         |                     
            //   5e                   | pop                 esi

        $sequence_22 = { 017e08 50 e8???????? ff0d???????? }
            // n = 4, score = 100
            //   017e08               | add                 dword ptr [esi + 8], edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff0d????????         |                     

        $sequence_23 = { 016b08 897b04 5f 5e }
            // n = 4, score = 100
            //   016b08               | add                 dword ptr [ebx + 8], ebp
            //   897b04               | mov                 dword ptr [ebx + 4], edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 835584
}