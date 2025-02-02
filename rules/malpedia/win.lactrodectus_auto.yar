rule win_lactrodectus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lactrodectus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lactrodectus"
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
        $sequence_0 = { 488b4c2428 0fbe09 3bc1 7512 }
            // n = 4, score = 300
            //   488b4c2428           | mov                 dword ptr [esp + 0x138], 0x16505e0
            //   0fbe09               | dec                 eax
            //   3bc1                 | lea                 eax, [0x75f6]
            //   7512                 | dec                 eax

        $sequence_1 = { c744242002000000 e9???????? 837c243406 7511 837c243801 750a }
            // n = 6, score = 300
            //   c744242002000000     | mov                 eax, dword ptr [esp + 0x40]
            //   e9????????           |                     
            //   837c243406           | add                 eax, edx
            //   7511                 | and                 eax, 0xff
            //   837c243801           | sub                 eax, edx
            //   750a                 | dec                 eax

        $sequence_2 = { 8b00 488b4c2430 488b09 0fbe0401 48634c2404 488b542428 0fbe0c0a }
            // n = 7, score = 300
            //   8b00                 | dec                 eax
            //   488b4c2430           | mov                 dword ptr [esp + 0x60], eax
            //   488b09               | imul                eax, eax, 0x3e8
            //   0fbe0401             | mov                 dword ptr [esp + 0xdc], eax
            //   48634c2404           | je                  0x1992
            //   488b542428           | xor                 edx, edx
            //   0fbe0c0a             | imul                eax, eax, 0x3e8

        $sequence_3 = { eb43 41b901000000 448b442424 488b542428 488b4c2448 e8???????? }
            // n = 6, score = 300
            //   eb43                 | dec                 eax
            //   41b901000000         | lea                 edx, [0xa84d]
            //   448b442424           | dec                 eax
            //   488b542428           | cmp                 dword ptr [esp + 0x48], 0
            //   488b4c2448           | je                  0x651
            //   e8????????           |                     

        $sequence_4 = { eb1f c744242000000000 4533c9 4533c0 }
            // n = 4, score = 300
            //   eb1f                 | dec                 eax
            //   c744242000000000     | lea                 eax, [esp + 0x150]
            //   4533c9               | dec                 eax
            //   4533c0               | mov                 dword ptr [esp + 0x120], eax

        $sequence_5 = { 488b4c2448 ff15???????? 89442444 837c244400 7502 eb11 }
            // n = 6, score = 300
            //   488b4c2448           | dec                 eax
            //   ff15????????         |                     
            //   89442444             | mov                 dword ptr [esp + 8], ecx
            //   837c244400           | dec                 eax
            //   7502                 | sub                 esp, 0x1c8
            //   eb11                 | cmp                 dword ptr [esp + 0x1d8], 0x12

        $sequence_6 = { 488d8c0c60020000 ba02000000 486bd200 4803ca 448bc0 488b542420 e8???????? }
            // n = 7, score = 300
            //   488d8c0c60020000     | lea                 ecx, [0xa4d8]
            //   ba02000000           | dec                 eax
            //   486bd200             | test                eax, eax
            //   4803ca               | je                  0x1519
            //   448bc0               | dec                 eax
            //   488b542420           | lea                 eax, [esp + 0x80]
            //   e8????????           |                     

        $sequence_7 = { 66c1ca08 0fb7d2 4c8b8424a0000000 450fb74006 6641c1c808 450fb7c0 4c8b8c24a0000000 }
            // n = 7, score = 300
            //   66c1ca08             | dec                 eax
            //   0fb7d2               | mov                 dword ptr [esp + 0x110], eax
            //   4c8b8424a0000000     | dec                 eax
            //   450fb74006           | mov                 eax, dword ptr [esp + 0x108]
            //   6641c1c808           | dec                 eax
            //   450fb7c0             | mov                 dword ptr [esp + 0x60], eax
            //   4c8b8c24a0000000     | mov                 dword ptr [esp + 0x58], 2

        $sequence_8 = { e8???????? b910000000 e8???????? 4889442448 488b442448 488b4c2450 488908 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   b910000000           | add                 ecx, edx
            //   e8????????           |                     
            //   4889442448           | mov                 ecx, 0x96
            //   488b442448           | div                 ecx
            //   488b4c2450           | mov                 eax, edx
            //   488908               | add                 eax, 0x1c2

        $sequence_9 = { 4889542410 48894c2408 4883ec78 c744243000000000 c744243400000000 488b942488000000 488d4c2448 }
            // n = 7, score = 300
            //   4889542410           | dec                 eax
            //   48894c2408           | mov                 dword ptr [esp + 0x298], eax
            //   4883ec78             | mov                 dword ptr [esp + 0x2a0], 0xcce95612
            //   c744243000000000     | dec                 eax
            //   c744243400000000     | lea                 eax, [0x6f67]
            //   488b942488000000     | dec                 eax
            //   488d4c2448           | mov                 dword ptr [esp + 0x2a8], eax

    condition:
        7 of them and filesize < 148480
}