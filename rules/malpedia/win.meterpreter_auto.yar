rule win_meterpreter_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.meterpreter."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.meterpreter"
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
        $sequence_0 = { 55 8bec dcec 088b55895356 108b3a85ff89 7dfc 750e }
            // n = 7, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   dcec                 | fsub                st(4), st(0)
            //   088b55895356         | or                  byte ptr [ebx + 0x56538955], cl
            //   108b3a85ff89         | adc                 byte ptr [ebx - 0x76007ac6], cl
            //   7dfc                 | jge                 0xfffffffe
            //   750e                 | jne                 0x10

        $sequence_1 = { fc b8c0150000 8b7508 33e5 257e040275 238b1d6a016a 006a00 }
            // n = 7, score = 200
            //   fc                   | cld                 
            //   b8c0150000           | mov                 eax, 0x15c0
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33e5                 | xor                 esp, ebp
            //   257e040275           | and                 eax, 0x7502047e
            //   238b1d6a016a         | and                 ecx, dword ptr [ebx + 0x6a016a1d]
            //   006a00               | add                 byte ptr [edx], ch

        $sequence_2 = { f1 57 52 bc40e84fff 38ff 83db14 5f }
            // n = 7, score = 200
            //   f1                   | int1                
            //   57                   | push                edi
            //   52                   | push                edx
            //   bc40e84fff           | mov                 esp, 0xff4fe840
            //   38ff                 | cmp                 bh, bh
            //   83db14               | sbb                 ebx, 0x14
            //   5f                   | pop                 edi

        $sequence_3 = { 314319 034319 83ebfc 0acb }
            // n = 4, score = 200
            //   314319               | xor                 dword ptr [ebx + 0x19], eax
            //   034319               | add                 eax, dword ptr [ebx + 0x19]
            //   83ebfc               | sub                 ebx, -4
            //   0acb                 | or                  cl, bl

        $sequence_4 = { 0000 68ffff0000 52 ffd7 8b2410 }
            // n = 5, score = 200
            //   0000                 | add                 byte ptr [eax], al
            //   68ffff0000           | push                0xffff
            //   52                   | push                edx
            //   ffd7                 | call                edi
            //   8b2410               | mov                 esp, dword ptr [eax + edx]

        $sequence_5 = { 8be5 5d c27f00 8d4df4 8d55ec }
            // n = 5, score = 200
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c27f00               | ret                 0x7f
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   8d55ec               | lea                 edx, [ebp - 0x14]

        $sequence_6 = { 51 6a00 6a00 37 0052bf 15???????? 85c0 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   37                   | aaa                 
            //   0052bf               | add                 byte ptr [edx - 0x41], dl
            //   15????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_7 = { 8b451c 8d07 a4 52 8d4d18 50 }
            // n = 6, score = 200
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]
            //   8d07                 | lea                 eax, [edi]
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   52                   | push                edx
            //   8d4d18               | lea                 ecx, [ebp + 0x18]
            //   50                   | push                eax

        $sequence_8 = { 41 00ff 15???????? 33c0 c3 7790 55 }
            // n = 7, score = 200
            //   41                   | inc                 ecx
            //   00ff                 | add                 bh, bh
            //   15????????           |                     
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 
            //   7790                 | ja                  0xffffff92
            //   55                   | push                ebp

        $sequence_9 = { 83ec08 53 8b4708 57 33ff 85db }
            // n = 6, score = 200
            //   83ec08               | sub                 esp, 8
            //   53                   | push                ebx
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   85db                 | test                ebx, ebx

    condition:
        7 of them and filesize < 188416
}