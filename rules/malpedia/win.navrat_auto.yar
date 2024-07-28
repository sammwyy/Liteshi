rule win_navrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.navrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.navrat"
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
        $sequence_0 = { 0fbec0 83e847 c3 8d48d0 80f909 }
            // n = 5, score = 300
            //   0fbec0               | movsx               eax, al
            //   83e847               | sub                 eax, 0x47
            //   c3                   | ret                 
            //   8d48d0               | lea                 ecx, [eax - 0x30]
            //   80f909               | cmp                 cl, 9

        $sequence_1 = { 56 68???????? 50 8d85f0feffff 8bf1 50 }
            // n = 6, score = 300
            //   56                   | push                esi
            //   68????????           |                     
            //   50                   | push                eax
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   8bf1                 | mov                 esi, ecx
            //   50                   | push                eax

        $sequence_2 = { f7de 1bf6 f7de 56 68???????? }
            // n = 5, score = 300
            //   f7de                 | neg                 esi
            //   1bf6                 | sbb                 esi, esi
            //   f7de                 | neg                 esi
            //   56                   | push                esi
            //   68????????           |                     

        $sequence_3 = { 8bf0 f7de 1bf6 f7de 56 }
            // n = 5, score = 300
            //   8bf0                 | mov                 esi, eax
            //   f7de                 | neg                 esi
            //   1bf6                 | sbb                 esi, esi
            //   f7de                 | neg                 esi
            //   56                   | push                esi

        $sequence_4 = { 0fbec0 83e847 c3 8d48d0 80f909 7707 }
            // n = 6, score = 300
            //   0fbec0               | movsx               eax, al
            //   83e847               | sub                 eax, 0x47
            //   c3                   | ret                 
            //   8d48d0               | lea                 ecx, [eax - 0x30]
            //   80f909               | cmp                 cl, 9
            //   7707                 | ja                  9

        $sequence_5 = { 7707 0fbec0 83c004 c3 3c2b 7503 }
            // n = 6, score = 300
            //   7707                 | ja                  9
            //   0fbec0               | movsx               eax, al
            //   83c004               | add                 eax, 4
            //   c3                   | ret                 
            //   3c2b                 | cmp                 al, 0x2b
            //   7503                 | jne                 5

        $sequence_6 = { c3 3c2f 0f95c0 fec8 2440 fec8 }
            // n = 6, score = 300
            //   c3                   | ret                 
            //   3c2f                 | cmp                 al, 0x2f
            //   0f95c0               | setne               al
            //   fec8                 | dec                 al
            //   2440                 | and                 al, 0x40
            //   fec8                 | dec                 al

        $sequence_7 = { 85f6 7407 8b7608 83461c02 }
            // n = 4, score = 300
            //   85f6                 | test                esi, esi
            //   7407                 | je                  9
            //   8b7608               | mov                 esi, dword ptr [esi + 8]
            //   83461c02             | add                 dword ptr [esi + 0x1c], 2

        $sequence_8 = { c745dc726f736f c745e066745c57 c745e4696e646f c745e877735c43 c745ec75727265 c745f06e745665 }
            // n = 6, score = 300
            //   c745dc726f736f       | mov                 dword ptr [ebp - 0x24], 0x6f736f72
            //   c745e066745c57       | mov                 dword ptr [ebp - 0x20], 0x575c7466
            //   c745e4696e646f       | mov                 dword ptr [ebp - 0x1c], 0x6f646e69
            //   c745e877735c43       | mov                 dword ptr [ebp - 0x18], 0x435c7377
            //   c745ec75727265       | mov                 dword ptr [ebp - 0x14], 0x65727275
            //   c745f06e745665       | mov                 dword ptr [ebp - 0x10], 0x6556746e

        $sequence_9 = { 51 56 50 57 a3???????? ff15???????? 57 }
            // n = 7, score = 300
            //   51                   | push                ecx
            //   56                   | push                esi
            //   50                   | push                eax
            //   57                   | push                edi
            //   a3????????           |                     
            //   ff15????????         |                     
            //   57                   | push                edi

    condition:
        7 of them and filesize < 352256
}