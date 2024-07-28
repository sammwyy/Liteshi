rule win_fatal_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.fatal_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fatal_rat"
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
        $sequence_0 = { 807dff00 742f 8b4e10 56 034df4 68???????? }
            // n = 6, score = 100
            //   807dff00             | cmp                 byte ptr [ebp - 1], 0
            //   742f                 | je                  0x31
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   56                   | push                esi
            //   034df4               | add                 ecx, dword ptr [ebp - 0xc]
            //   68????????           |                     

        $sequence_1 = { 55 8bec 8b4508 33d2 3bc2 7432 8b481c }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   33d2                 | xor                 edx, edx
            //   3bc2                 | cmp                 eax, edx
            //   7432                 | je                  0x34
            //   8b481c               | mov                 ecx, dword ptr [eax + 0x1c]

        $sequence_2 = { 833d????????02 7513 68???????? 8d851cffffff 50 e8???????? 59 }
            // n = 7, score = 100
            //   833d????????02       |                     
            //   7513                 | jne                 0x15
            //   68????????           |                     
            //   8d851cffffff         | lea                 eax, [ebp - 0xe4]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_3 = { c645bb46 c645bc6f c645bd72 c645be6d 885dbf ff15???????? }
            // n = 6, score = 100
            //   c645bb46             | mov                 byte ptr [ebp - 0x45], 0x46
            //   c645bc6f             | mov                 byte ptr [ebp - 0x44], 0x6f
            //   c645bd72             | mov                 byte ptr [ebp - 0x43], 0x72
            //   c645be6d             | mov                 byte ptr [ebp - 0x42], 0x6d
            //   885dbf               | mov                 byte ptr [ebp - 0x41], bl
            //   ff15????????         |                     

        $sequence_4 = { 8b7df8 899e90000000 80662d00 8bce e8???????? 8b8e90000000 8b4614 }
            // n = 7, score = 100
            //   8b7df8               | mov                 edi, dword ptr [ebp - 8]
            //   899e90000000         | mov                 dword ptr [esi + 0x90], ebx
            //   80662d00             | and                 byte ptr [esi + 0x2d], 0
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8b8e90000000         | mov                 ecx, dword ptr [esi + 0x90]
            //   8b4614               | mov                 eax, dword ptr [esi + 0x14]

        $sequence_5 = { 48 eb05 8b462c 2bc1 8945f0 8b4508 8b0485d0b40110 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   eb05                 | jmp                 7
            //   8b462c               | mov                 eax, dword ptr [esi + 0x2c]
            //   2bc1                 | sub                 eax, ecx
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b0485d0b40110       | mov                 eax, dword ptr [eax*4 + 0x1001b4d0]

        $sequence_6 = { c685e0fdffff2e c685e1fdffff65 c685e2fdffff78 c685e3fdffff65 889de4fdffff c645946b c6459573 }
            // n = 7, score = 100
            //   c685e0fdffff2e       | mov                 byte ptr [ebp - 0x220], 0x2e
            //   c685e1fdffff65       | mov                 byte ptr [ebp - 0x21f], 0x65
            //   c685e2fdffff78       | mov                 byte ptr [ebp - 0x21e], 0x78
            //   c685e3fdffff65       | mov                 byte ptr [ebp - 0x21d], 0x65
            //   889de4fdffff         | mov                 byte ptr [ebp - 0x21c], bl
            //   c645946b             | mov                 byte ptr [ebp - 0x6c], 0x6b
            //   c6459573             | mov                 byte ptr [ebp - 0x6b], 0x73

        $sequence_7 = { 8981a4af0600 5d c3 c3 c3 55 8bec }
            // n = 7, score = 100
            //   8981a4af0600         | mov                 dword ptr [ecx + 0x6afa4], eax
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   c3                   | ret                 
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_8 = { 33db a5 a5 53 8d8520feffff 6a2e 50 }
            // n = 7, score = 100
            //   33db                 | xor                 ebx, ebx
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   53                   | push                ebx
            //   8d8520feffff         | lea                 eax, [ebp - 0x1e0]
            //   6a2e                 | push                0x2e
            //   50                   | push                eax

        $sequence_9 = { ff15???????? 53 56 50 a3???????? ff15???????? 80a5ecfbffff00 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   56                   | push                esi
            //   50                   | push                eax
            //   a3????????           |                     
            //   ff15????????         |                     
            //   80a5ecfbffff00       | and                 byte ptr [ebp - 0x414], 0

    condition:
        7 of them and filesize < 344064
}