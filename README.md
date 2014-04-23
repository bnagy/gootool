gootool
=======

Silly PoC of a limited otool clone based on the capstone disassembly lib

Eventually aiming to produce silly graph output with D3.js

This is a toy, not a tool.

TODO:
=======

Next step is to code the CFG architecture and write a transformer for each BBL to a Node struct with edges and whatever other metadata. After that, add the D3 html template code, CSS, etc, then write a transformer for the CFG nodes to the required raw data as JSON.

Screenshot
=======

```
_parse_size_t:
0x10000de00: 55                       push        rbp
0x10000de01: 4889e5                   mov         rbp, rsp
0x10000de04: 4883ec20                 sub         rsp, 0x20
0x10000de08: 488d35bd2d0000           lea         rsi, qword ptr [rip + 0x2dbd]
0x10000de0f: 488d55e8                 lea         rdx, qword ptr [rbp + 0xffffffffffffffe8]
0x10000de13: 488d4df6                 lea         rcx, qword ptr [rbp + 0xfffffffffffffff6]
0x10000de17: 48897df8                 mov         qword ptr [rbp + 0xfffffffffffffff8], rdi
0x10000de1b: 488b7df8                 mov         rdi, qword ptr [rbp + 0xfffffffffffffff8]
0x10000de1f: b000                     mov         al, 0
0x10000de21: e836170000               call        STUB_sscanf [ 0x10000f55c ]
0x10000de26: 41b801000000             mov         r8d, 1
0x10000de2c: 4188c1                   mov         r9b, al
0x10000de2f: 44884df7                 mov         byte ptr [rbp + 0xfffffffffffffff7], r9b
0x10000de33: 0fbe45f7                 movsx       eax, byte ptr [rbp + 0xfffffffffffffff7]
0x10000de37: 4139c0                   cmp         r8d, eax
0x10000de3a: 0f841c000000             je          loc_0x10000de5c [ 0x10000de5c ]

loc_0x10000de40:
0x10000de40: 488d3d8b2d0000           lea         rdi, qword ptr [rip + 0x2d8b]
0x10000de47: 488b75f8                 mov         rsi, qword ptr [rbp + 0xfffffffffffffff8]
0x10000de4b: b000                     mov         al, 0
0x10000de4d: e87ef3ffff               call        _warnx [ 0x10000d1d0 ]
0x10000de52: bf05000000               mov         edi, 5
0x10000de57: e814000000               call        _usage [ 0x10000de70 ]

loc_0x10000de5c:
0x10000de5c: 488b45e8                 mov         rax, qword ptr [rbp + 0xffffffffffffffe8]
0x10000de60: 4883c420                 add         rsp, 0x20
0x10000de64: 5d                       pop         rbp
0x10000de65: c3                       ret
0x10000de66: 662e0f1f840000000000     nop         word ptr cs:[rax + rax]
```

BUGS
=======

This is definitely going to fail spectacularly on any kind of obfuscated binary of any kind. Also, Go's macho parser doesn't seem to recognise some magic values, so some binaries just won't parse at all.

Contributing
=======

As if.


