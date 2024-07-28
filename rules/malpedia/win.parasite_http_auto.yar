rule win_parasite_http_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.parasite_http."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.parasite_http"
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
        $sequence_0 = { 57 b900040000 e8???????? 8bf8 85ff 0f848a000000 56 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   b900040000           | mov                 ecx, 0x400
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   0f848a000000         | je                  0x90
            //   56                   | push                esi

        $sequence_1 = { 50 33c0 895dfc 53 53 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   33c0                 | xor                 eax, eax
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   53                   | push                ebx
            //   53                   | push                ebx

        $sequence_2 = { 884df2 8d4dbc 66895dbe 668955c0 66895dc4 668945ce 66c745ec5669 }
            // n = 7, score = 100
            //   884df2               | mov                 byte ptr [ebp - 0xe], cl
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]
            //   66895dbe             | mov                 word ptr [ebp - 0x42], bx
            //   668955c0             | mov                 word ptr [ebp - 0x40], dx
            //   66895dc4             | mov                 word ptr [ebp - 0x3c], bx
            //   668945ce             | mov                 word ptr [ebp - 0x32], ax
            //   66c745ec5669         | mov                 word ptr [ebp - 0x14], 0x6956

        $sequence_3 = { e8???????? 59 85db 7407 8bcb e8???????? 8b45f0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85db                 | test                ebx, ebx
            //   7407                 | je                  9
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_4 = { 6a36 6689460a 58 6a34 6689460e 58 57 }
            // n = 7, score = 100
            //   6a36                 | push                0x36
            //   6689460a             | mov                 word ptr [esi + 0xa], ax
            //   58                   | pop                 eax
            //   6a34                 | push                0x34
            //   6689460e             | mov                 word ptr [esi + 0xe], ax
            //   58                   | pop                 eax
            //   57                   | push                edi

        $sequence_5 = { e8???????? b9???????? 8bd8 e8???????? 33d2 8bcb }
            // n = 6, score = 100
            //   e8????????           |                     
            //   b9????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   e8????????           |                     
            //   33d2                 | xor                 edx, edx
            //   8bcb                 | mov                 ecx, ebx

        $sequence_6 = { 57 8bf9 b9???????? e8???????? b9???????? 8bf0 e8???????? }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8bf9                 | mov                 edi, ecx
            //   b9????????           |                     
            //   e8????????           |                     
            //   b9????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     

        $sequence_7 = { 57 e8???????? 03c6 50 52 }
            // n = 5, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax
            //   52                   | push                edx

        $sequence_8 = { 740f 8d4dfc 51 51 51 50 }
            // n = 6, score = 100
            //   740f                 | je                  0x11
            //   8d4dfc               | lea                 ecx, [ebp - 4]
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_9 = { 53 ffd0 8bcf e8???????? 8bce e8???????? 8bcb }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   ffd0                 | call                eax
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8bcb                 | mov                 ecx, ebx

    condition:
        7 of them and filesize < 147456
}