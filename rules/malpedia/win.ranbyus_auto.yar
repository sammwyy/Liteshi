rule win_ranbyus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.ranbyus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ranbyus"
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
        $sequence_0 = { 7504 83c8ff c3 c7402401000000 }
            // n = 4, score = 1100
            //   7504                 | jne                 6
            //   83c8ff               | or                  eax, 0xffffffff
            //   c3                   | ret                 
            //   c7402401000000       | mov                 dword ptr [eax + 0x24], 1

        $sequence_1 = { 894608 8b44241c 56 68???????? 89460c }
            // n = 5, score = 1100
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   56                   | push                esi
            //   68????????           |                     
            //   89460c               | mov                 dword ptr [esi + 0xc], eax

        $sequence_2 = { 83c414 85f6 7414 6a01 6a01 57 }
            // n = 6, score = 1100
            //   83c414               | add                 esp, 0x14
            //   85f6                 | test                esi, esi
            //   7414                 | je                  0x16
            //   6a01                 | push                1
            //   6a01                 | push                1
            //   57                   | push                edi

        $sequence_3 = { 760a 814e2500500000 c6060f 0fb606 5e 5b }
            // n = 6, score = 1100
            //   760a                 | jbe                 0xc
            //   814e2500500000       | or                  dword ptr [esi + 0x25], 0x5000
            //   c6060f               | mov                 byte ptr [esi], 0xf
            //   0fb606               | movzx               eax, byte ptr [esi]
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_4 = { a1???????? eb09 83780400 7507 8b4034 85c0 }
            // n = 6, score = 1100
            //   a1????????           |                     
            //   eb09                 | jmp                 0xb
            //   83780400             | cmp                 dword ptr [eax + 4], 0
            //   7507                 | jne                 9
            //   8b4034               | mov                 eax, dword ptr [eax + 0x34]
            //   85c0                 | test                eax, eax

        $sequence_5 = { e8???????? 59 8b4e05 89410b 8b4605 39780b 7407 }
            // n = 7, score = 1100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4e05               | mov                 ecx, dword ptr [esi + 5]
            //   89410b               | mov                 dword ptr [ecx + 0xb], eax
            //   8b4605               | mov                 eax, dword ptr [esi + 5]
            //   39780b               | cmp                 dword ptr [eax + 0xb], edi
            //   7407                 | je                  9

        $sequence_6 = { 8b4e05 89410b 8b4605 39780b }
            // n = 4, score = 1100
            //   8b4e05               | mov                 ecx, dword ptr [esi + 5]
            //   89410b               | mov                 dword ptr [ecx + 0xb], eax
            //   8b4605               | mov                 eax, dword ptr [esi + 5]
            //   39780b               | cmp                 dword ptr [eax + 0xb], edi

        $sequence_7 = { 83c621 8a06 3c46 7240 3c47 }
            // n = 5, score = 1100
            //   83c621               | add                 esi, 0x21
            //   8a06                 | mov                 al, byte ptr [esi]
            //   3c46                 | cmp                 al, 0x46
            //   7240                 | jb                  0x42
            //   3c47                 | cmp                 al, 0x47

        $sequence_8 = { 83780400 7507 8b4034 85c0 75f3 c3 }
            // n = 6, score = 1100
            //   83780400             | cmp                 dword ptr [eax + 4], 0
            //   7507                 | jne                 9
            //   8b4034               | mov                 eax, dword ptr [eax + 0x34]
            //   85c0                 | test                eax, eax
            //   75f3                 | jne                 0xfffffff5
            //   c3                   | ret                 

        $sequence_9 = { c3 837c240800 7467 8b44240c }
            // n = 4, score = 1100
            //   c3                   | ret                 
            //   837c240800           | cmp                 dword ptr [esp + 8], 0
            //   7467                 | je                  0x69
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]

    condition:
        7 of them and filesize < 638976
}