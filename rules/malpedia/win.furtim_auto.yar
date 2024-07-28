rule win_furtim_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.furtim."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.furtim"
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
        $sequence_0 = { 5f 5e c9 c20400 6a0c 68???????? e8???????? }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c20400               | ret                 4
            //   6a0c                 | push                0xc
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_1 = { 85c0 7c28 8d45fc 50 6a04 ff15???????? }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7c28                 | jl                  0x2a
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   6a04                 | push                4
            //   ff15????????         |                     

        $sequence_2 = { c7867802000020d94000 c78600050000cb224000 c786f406000032164000 c746601c724400 c7869c06000032254000 c786fc020000ca254000 }
            // n = 6, score = 100
            //   c7867802000020d94000     | mov    dword ptr [esi + 0x278], 0x40d920
            //   c78600050000cb224000     | mov    dword ptr [esi + 0x500], 0x4022cb
            //   c786f406000032164000     | mov    dword ptr [esi + 0x6f4], 0x401632
            //   c746601c724400       | mov                 dword ptr [esi + 0x60], 0x44721c
            //   c7869c06000032254000     | mov    dword ptr [esi + 0x69c], 0x402532
            //   c786fc020000ca254000     | mov    dword ptr [esi + 0x2fc], 0x4025ca

        $sequence_3 = { 59 85c0 7408 8bce ff96cc050000 5f }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   8bce                 | mov                 ecx, esi
            //   ff96cc050000         | call                dword ptr [esi + 0x5cc]
            //   5f                   | pop                 edi

        $sequence_4 = { 57 8bf1 8dbeb8000000 57 c7071c010000 ff96bc030000 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   8bf1                 | mov                 esi, ecx
            //   8dbeb8000000         | lea                 edi, [esi + 0xb8]
            //   57                   | push                edi
            //   c7071c010000         | mov                 dword ptr [edi], 0x11c
            //   ff96bc030000         | call                dword ptr [esi + 0x3bc]

        $sequence_5 = { c9 c20800 8bff 55 8bec 83ec10 ff7508 }
            // n = 7, score = 100
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_6 = { 0f85e3000000 39a9c0000000 7542 0fb781cc010000 663bc5 7405 663bc3 }
            // n = 7, score = 100
            //   0f85e3000000         | jne                 0xe9
            //   39a9c0000000         | cmp                 dword ptr [ecx + 0xc0], ebp
            //   7542                 | jne                 0x44
            //   0fb781cc010000       | movzx               eax, word ptr [ecx + 0x1cc]
            //   663bc5               | cmp                 ax, bp
            //   7405                 | je                  7
            //   663bc3               | cmp                 ax, bx

        $sequence_7 = { 740f 837dfc01 7509 c686c405000001 eb0e 8bce ff96f8040000 }
            // n = 7, score = 100
            //   740f                 | je                  0x11
            //   837dfc01             | cmp                 dword ptr [ebp - 4], 1
            //   7509                 | jne                 0xb
            //   c686c405000001       | mov                 byte ptr [esi + 0x5c4], 1
            //   eb0e                 | jmp                 0x10
            //   8bce                 | mov                 ecx, esi
            //   ff96f8040000         | call                dword ptr [esi + 0x4f8]

        $sequence_8 = { c745e4e4624400 c745e8ec624400 c745ecf4624400 c745f0fc624400 c745f404634400 c745f8???????? }
            // n = 6, score = 100
            //   c745e4e4624400       | mov                 dword ptr [ebp - 0x1c], 0x4462e4
            //   c745e8ec624400       | mov                 dword ptr [ebp - 0x18], 0x4462ec
            //   c745ecf4624400       | mov                 dword ptr [ebp - 0x14], 0x4462f4
            //   c745f0fc624400       | mov                 dword ptr [ebp - 0x10], 0x4462fc
            //   c745f404634400       | mov                 dword ptr [ebp - 0xc], 0x446304
            //   c745f8????????       |                     

        $sequence_9 = { 389f94010000 7546 80bf9501000015 7535 80bf960100005d 752c 8bce }
            // n = 7, score = 100
            //   389f94010000         | cmp                 byte ptr [edi + 0x194], bl
            //   7546                 | jne                 0x48
            //   80bf9501000015       | cmp                 byte ptr [edi + 0x195], 0x15
            //   7535                 | jne                 0x37
            //   80bf960100005d       | cmp                 byte ptr [edi + 0x196], 0x5d
            //   752c                 | jne                 0x2e
            //   8bce                 | mov                 ecx, esi

    condition:
        7 of them and filesize < 622592
}