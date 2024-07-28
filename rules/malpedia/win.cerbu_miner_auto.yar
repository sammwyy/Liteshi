rule win_cerbu_miner_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.cerbu_miner."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cerbu_miner"
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
        $sequence_0 = { 88b42480000000 eb3f 83e902 7433 83e904 7413 83e909 }
            // n = 7, score = 100
            //   88b42480000000       | mov                 byte ptr [esp + 0x80], dh
            //   eb3f                 | jmp                 0x41
            //   83e902               | sub                 ecx, 2
            //   7433                 | je                  0x35
            //   83e904               | sub                 ecx, 4
            //   7413                 | je                  0x15
            //   83e909               | sub                 ecx, 9

        $sequence_1 = { 7412 48 8d0d0b360500 48 83c428 48 ff25???????? }
            // n = 7, score = 100
            //   7412                 | je                  0x14
            //   48                   | dec                 eax
            //   8d0d0b360500         | lea                 ecx, [0x5360b]
            //   48                   | dec                 eax
            //   83c428               | add                 esp, 0x28
            //   48                   | dec                 eax
            //   ff25????????         |                     

        $sequence_2 = { 8d4601 c643012e 48 63c8 41 8d4602 48 }
            // n = 7, score = 100
            //   8d4601               | lea                 eax, [esi + 1]
            //   c643012e             | mov                 byte ptr [ebx + 1], 0x2e
            //   48                   | dec                 eax
            //   63c8                 | arpl                ax, cx
            //   41                   | inc                 ecx
            //   8d4602               | lea                 eax, [esi + 2]
            //   48                   | dec                 eax

        $sequence_3 = { 85d2 7427 85c9 b800040000 41 b800080000 44 }
            // n = 7, score = 100
            //   85d2                 | test                edx, edx
            //   7427                 | je                  0x29
            //   85c9                 | test                ecx, ecx
            //   b800040000           | mov                 eax, 0x400
            //   41                   | inc                 ecx
            //   b800080000           | mov                 eax, 0x800
            //   44                   | inc                 esp

        $sequence_4 = { f6473801 7402 eb18 48 8bcf ff15???????? f6473801 }
            // n = 7, score = 100
            //   f6473801             | test                byte ptr [edi + 0x38], 1
            //   7402                 | je                  4
            //   eb18                 | jmp                 0x1a
            //   48                   | dec                 eax
            //   8bcf                 | mov                 ecx, edi
            //   ff15????????         |                     
            //   f6473801             | test                byte ptr [edi + 0x38], 1

        $sequence_5 = { e9???????? 45 8bfd 44 89ad50010000 e9???????? 44 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   45                   | inc                 ebp
            //   8bfd                 | mov                 edi, ebp
            //   44                   | inc                 esp
            //   89ad50010000         | mov                 dword ptr [ebp + 0x150], ebp
            //   e9????????           |                     
            //   44                   | inc                 esp

        $sequence_6 = { 48 89442420 e8???????? 48 8bd7 48 8bcb }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8bd7                 | mov                 edx, edi
            //   48                   | dec                 eax
            //   8bcb                 | mov                 ecx, ebx

        $sequence_7 = { 89b42418010000 8b74242c 83feff 7515 837f0c00 7c0f 48 }
            // n = 7, score = 100
            //   89b42418010000       | mov                 dword ptr [esp + 0x118], esi
            //   8b74242c             | mov                 esi, dword ptr [esp + 0x2c]
            //   83feff               | cmp                 esi, -1
            //   7515                 | jne                 0x17
            //   837f0c00             | cmp                 dword ptr [edi + 0xc], 0
            //   7c0f                 | jl                  0x11
            //   48                   | dec                 eax

        $sequence_8 = { 8d057b52f9ff 48 894518 c745b0e6070000 48 c745c000000200 48 }
            // n = 7, score = 100
            //   8d057b52f9ff         | lea                 eax, [0xfff9527b]
            //   48                   | dec                 eax
            //   894518               | mov                 dword ptr [ebp + 0x18], eax
            //   c745b0e6070000       | mov                 dword ptr [ebp - 0x50], 0x7e6
            //   48                   | dec                 eax
            //   c745c000000200       | mov                 dword ptr [ebp - 0x40], 0x20000
            //   48                   | dec                 eax

        $sequence_9 = { 44 2bc0 44 8903 33c0 48 8b5c2438 }
            // n = 7, score = 100
            //   44                   | inc                 esp
            //   2bc0                 | sub                 eax, eax
            //   44                   | inc                 esp
            //   8903                 | mov                 dword ptr [ebx], eax
            //   33c0                 | xor                 eax, eax
            //   48                   | dec                 eax
            //   8b5c2438             | mov                 ebx, dword ptr [esp + 0x38]

    condition:
        7 of them and filesize < 1040384
}