gootool
=======

Silly PoC of a limited otool clone based on the capstone disassembly lib

Eventually aiming to produce silly graph output with D3.js

This is a toy, not a tool.

TODO:
=======

Next step is to add the D3 html template code, CSS, etc, then write a transformer for the CFG nodes to the required raw data as JSON.

Screenshot
=======
( you can see the True / False jmp edges, and the lame dead code detection, showing a dead Tail: 1)

```
loc_0x206f1 Len: 5 Tail: 0 Edges: T:0x20716 F:0x20703 A:0x0

loc_0x206f1:
0x206f1: 8d83d4ba0900             lea         eax, dword ptr [rbx + 0x9bad4]
0x206f7: 8b00                     mov         eax, dword ptr [rax]
0x206f9: 8b80a4010000             mov         eax, dword ptr [rax + 0x1a4]
0x206ff: 85c0                     test        eax, eax
0x20701: 7513                     jne         loc_0x20716 [ 0x20716 ]

loc_0x73d08 Len: 11 Tail: 0 Edges: T:0x0 F:0x0 A:0x73d35

loc_0x73d08:
0x73d08: 8b45b0                   mov         eax, dword ptr [rbp + 0xffffffffffffffb0]
0x73d0b: b9ffffffff               mov         ecx, 0xffffffff
0x73d10: 898574ffffff             mov         dword ptr [rbp + 0xffffffffffffff74], eax
0x73d16: b800000000               mov         eax, 0
0x73d1b: fc                       cld
0x73d1c: 8bbd74ffffff             mov         edi, dword ptr [rbp + 0xffffffffffffff74]
0x73d22: f2ae                     repne scasb al, byte ptr es:[rdi]
0x73d24: 89c8                     mov         eax, ecx
0x73d26: f7d0                     not         eax
0x73d28: 48894584                 mov         qword ptr [rbp + 0xffffffffffffff84], rax
0x73d2c: eb07                     jmp         loc_0x73d35 [ 0x73d35 ]

_gpg_error_from_syserror Len: 8 Tail: 1 Edges: T:0x0 F:0x0 A:0x0

_gpg_error_from_syserror:
0xdb8e: 55                       push        rbp
0xdb8f: 89e5                     mov         ebp, esp
0xdb91: 83ec18                   sub         esp, 0x18
0xdb94: e89bd00a00               call        STUB_gpg_err_code_from_syserror [ 0xbac34 ]
0xdb99: 890424                   mov         dword ptr [rsp], eax
0xdb9c: e817f7ffff               call        _gpg_error [ 0xd2b8 ]
0xdba1: c9                       leave
0xdba2: c3                       ret
0xdba3: 90                       nop
```

BUGS
=======

This is definitely going to fail spectacularly on any kind of obfuscated binary. Also, Go's macho parser doesn't seem to recognise some magic values, so some binaries just won't parse at all.

- dead code detection at the end of blocks is pretty crappy
- Doesn't work on Fat binaries, only native Mach-O
- Unlikely to work on 32 bit, don't have dinohardware; don't care.

Contributing
=======

Yes. Please to writing rest of web bigdata interface for clouds. Thx.

License
=======

None. BSD, whatever. This is a toy not a tool.


