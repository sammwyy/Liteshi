rule win_acronym_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.acronym."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.acronym"
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
        $sequence_0 = { 89550c 8b4510 034508 8a08 884dff 8b5510 03550c }
            // n = 7, score = 100
            //   89550c               | mov                 dword ptr [ebp + 0xc], edx
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   034508               | add                 eax, dword ptr [ebp + 8]
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   884dff               | mov                 byte ptr [ebp - 1], cl
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   03550c               | add                 edx, dword ptr [ebp + 0xc]

        $sequence_1 = { 8b55e8 8a45f4 88040a ebac 33c9 75fc 8be5 }
            // n = 7, score = 100
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   8a45f4               | mov                 al, byte ptr [ebp - 0xc]
            //   88040a               | mov                 byte ptr [edx + ecx], al
            //   ebac                 | jmp                 0xffffffae
            //   33c9                 | xor                 ecx, ecx
            //   75fc                 | jne                 0xfffffffe
            //   8be5                 | mov                 esp, ebp

        $sequence_2 = { 50 ff15???????? 8945f8 8b4dfc 8b5110 52 8b45fc }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b5110               | mov                 edx, dword ptr [ecx + 0x10]
            //   52                   | push                edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_3 = { e8???????? 8bc8 e8???????? 0fb6d0 85d2 0f85d4000000 8b450c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   0fb6d0               | movzx               edx, al
            //   85d2                 | test                edx, edx
            //   0f85d4000000         | jne                 0xda
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_4 = { c745fc00000000 eb09 8b45fc 83c001 8945fc 8b4df4 83c104 }
            // n = 7, score = 100
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   eb09                 | jmp                 0xb
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83c001               | add                 eax, 1
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   83c104               | add                 ecx, 4

        $sequence_5 = { 6a00 6a00 ff15???????? b901000000 85c9 0f84fd000000 c745f000000000 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   b901000000           | mov                 ecx, 1
            //   85c9                 | test                ecx, ecx
            //   0f84fd000000         | je                  0x103
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0

        $sequence_6 = { 2b55bc 8955b8 8b45b8 8945cc 33c9 75fc 8b55dc }
            // n = 7, score = 100
            //   2b55bc               | sub                 edx, dword ptr [ebp - 0x44]
            //   8955b8               | mov                 dword ptr [ebp - 0x48], edx
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   33c9                 | xor                 ecx, ecx
            //   75fc                 | jne                 0xfffffffe
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]

        $sequence_7 = { 8b0c90 83c101 8b55f4 8b45f0 0fb754505e 8b45ec 69c008040000 }
            // n = 7, score = 100
            //   8b0c90               | mov                 ecx, dword ptr [eax + edx*4]
            //   83c101               | add                 ecx, 1
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   0fb754505e           | movzx               edx, word ptr [eax + edx*2 + 0x5e]
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   69c008040000         | imul                eax, eax, 0x408

        $sequence_8 = { 8b4508 50 e8???????? 83c410 ebaa 8b45c4 69c0c51d0000 }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   ebaa                 | jmp                 0xffffffac
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   69c0c51d0000         | imul                eax, eax, 0x1dc5

        $sequence_9 = { 69d208040000 8b7508 8d941660b10000 89048a 8b45f4 8b4df0 0fb754411c }
            // n = 7, score = 100
            //   69d208040000         | imul                edx, edx, 0x408
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8d941660b10000       | lea                 edx, [esi + edx + 0xb160]
            //   89048a               | mov                 dword ptr [edx + ecx*4], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   0fb754411c           | movzx               edx, word ptr [ecx + eax*2 + 0x1c]

    condition:
        7 of them and filesize < 466944
}