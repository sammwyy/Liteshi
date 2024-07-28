rule win_thanatos_ransom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.thanatos_ransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thanatos_ransom"
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
        $sequence_0 = { 50 ff75e0 e8???????? 8b4df8 8bc7 5f 33cd }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   e8????????           |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   33cd                 | xor                 ecx, ebp

        $sequence_1 = { 8b00 8bc8 e8???????? c645fc0a }
            // n = 4, score = 100
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   c645fc0a             | mov                 byte ptr [ebp - 4], 0xa

        $sequence_2 = { 50 e8???????? 56 8bd0 c645fc04 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   56                   | push                esi
            //   8bd0                 | mov                 edx, eax
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4

        $sequence_3 = { 83c404 c60300 ff15???????? 50 e8???????? be14000000 }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   c60300               | mov                 byte ptr [ebx], 0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   be14000000           | mov                 esi, 0x14

        $sequence_4 = { c745500f000000 c7454c00000000 c6453c00 83f810 7242 8b4d54 }
            // n = 6, score = 100
            //   c745500f000000       | mov                 dword ptr [ebp + 0x50], 0xf
            //   c7454c00000000       | mov                 dword ptr [ebp + 0x4c], 0
            //   c6453c00             | mov                 byte ptr [ebp + 0x3c], 0
            //   83f810               | cmp                 eax, 0x10
            //   7242                 | jb                  0x44
            //   8b4d54               | mov                 ecx, dword ptr [ebp + 0x54]

        $sequence_5 = { 88441de8 43 8975e0 83fb04 757c 33f6 8a4435e8 }
            // n = 7, score = 100
            //   88441de8             | mov                 byte ptr [ebp + ebx - 0x18], al
            //   43                   | inc                 ebx
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   83fb04               | cmp                 ebx, 4
            //   757c                 | jne                 0x7e
            //   33f6                 | xor                 esi, esi
            //   8a4435e8             | mov                 al, byte ptr [ebp + esi - 0x18]

        $sequence_6 = { 8b0c85e0774300 8a06 46 8844392c 2bf2 eb14 }
            // n = 6, score = 100
            //   8b0c85e0774300       | mov                 ecx, dword ptr [eax*4 + 0x4377e0]
            //   8a06                 | mov                 al, byte ptr [esi]
            //   46                   | inc                 esi
            //   8844392c             | mov                 byte ptr [ecx + edi + 0x2c], al
            //   2bf2                 | sub                 esi, edx
            //   eb14                 | jmp                 0x16

        $sequence_7 = { 0f8580000000 8b4508 dd00 ebc6 c745e0a0bd4200 e9???????? }
            // n = 6, score = 100
            //   0f8580000000         | jne                 0x86
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   dd00                 | fld                 qword ptr [eax]
            //   ebc6                 | jmp                 0xffffffc8
            //   c745e0a0bd4200       | mov                 dword ptr [ebp - 0x20], 0x42bda0
            //   e9????????           |                     

        $sequence_8 = { 40 8d4de0 50 ff75e0 e8???????? 8b4df8 }
            // n = 6, score = 100
            //   40                   | inc                 eax
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   50                   | push                eax
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   e8????????           |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_9 = { e8???????? c70021000000 e9???????? 894ddc c745e034bf4200 e9???????? c745e030bf4200 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c70021000000         | mov                 dword ptr [eax], 0x21
            //   e9????????           |                     
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx
            //   c745e034bf4200       | mov                 dword ptr [ebp - 0x20], 0x42bf34
            //   e9????????           |                     
            //   c745e030bf4200       | mov                 dword ptr [ebp - 0x20], 0x42bf30

    condition:
        7 of them and filesize < 516096
}