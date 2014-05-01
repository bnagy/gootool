gootool
=======

Silly PoC of a limited otool clone based on the capstone disassembly lib

Eventually aiming to produce lame graph output to troll Halvar

This is a toy, not a tool.

TODO:
=======

Graph transforms and http server

Screenshot
=======

```
(0x10000d5d0): _zalloc Len: 9 Tail: 0 Edges:  T: loc_0x10000d64f F: loc_0x10000d5f6 Calls ==> [ STUB_malloc  ___inline_memset_chk  STUB___memset_chk ]
	0x10000d5d0: 55                       push        rbp
	0x10000d5d1: 4889e5                   mov         rbp, rsp
	0x10000d5d4: 4883ec30                 sub         rsp, 0x30
	0x10000d5d8: 897dfc                   mov         dword ptr [rbp + 0xfffffffffffffffc], edi
	0x10000d5db: 48637dfc                 movsxd      rdi, dword ptr [rbp + 0xfffffffffffffffc]
	0x10000d5df: e8181f0000               call        STUB_malloc
	0x10000d5e4: 488945f0                 mov         qword ptr [rbp + 0xfffffffffffffff0], rax
	0x10000d5e8: 48817df000000000         cmp         qword ptr [rbp + 0xfffffffffffffff0], 0
	0x10000d5f0: 0f8459000000             je          loc_0x10000d64f
loc_0x10000d5f6 Len: 5 Tail: 0 Edges:  T: loc_0x10000d639 F: loc_0x10000d614
	0x10000d5f6: 48b8ffffffffffffffff     movabs      rax, -1
	0x10000d600: 488b4df0                 mov         rcx, qword ptr [rbp + 0xfffffffffffffff0]
	0x10000d604: 483dffffffff             cmp         rax, -1
	0x10000d60a: 48894de8                 mov         qword ptr [rbp + 0xffffffffffffffe8], rcx
	0x10000d60e: 0f8425000000             je          loc_0x10000d639
loc_0x10000d614 Len: 7 Tail: 0 Edges:  A: loc_0x10000d64f Calls ==> [ STUB___memset_chk ]
	0x10000d614: be00000000               mov         esi, 0
	0x10000d619: 48b9ffffffffffffffff     movabs      rcx, -1
	0x10000d623: 488b7df0                 mov         rdi, qword ptr [rbp + 0xfffffffffffffff0]
	0x10000d627: 486355fc                 movsxd      rdx, dword ptr [rbp + 0xfffffffffffffffc]
	0x10000d62b: e80c1e0000               call        STUB___memset_chk
	0x10000d630: 488945e0                 mov         qword ptr [rbp + 0xffffffffffffffe0], rax
	0x10000d634: e916000000               jmp         loc_0x10000d64f
loc_0x10000d639 Len: 5 Tail: 0 Edges:  A: loc_0x10000d64f Calls ==> [ ___inline_memset_chk ]
	0x10000d639: be00000000               mov         esi, 0
	0x10000d63e: 488b7df0                 mov         rdi, qword ptr [rbp + 0xfffffffffffffff0]
	0x10000d642: 486355fc                 movsxd      rdx, dword ptr [rbp + 0xfffffffffffffffc]
	0x10000d646: e815000000               call        ___inline_memset_chk
	0x10000d64b: 488945d8                 mov         qword ptr [rbp + 0xffffffffffffffd8], rax
loc_0x10000d64f Len: 4 Tail: 1 Edges:  [terminal]
	0x10000d64f: 488b45f0                 mov         rax, qword ptr [rbp + 0xfffffffffffffff0]
	0x10000d653: 4883c430                 add         rsp, 0x30
	0x10000d657: 5d                       pop         rbp
	0x10000d658: c3                       ret
```

BUGS
=======

This is definitely going to fail spectacularly on any kind of obfuscated binary. It's also pretty crappy without symbols, but it does its best.

- dead code detection at the end of blocks is pretty crappy
- Doesn't work on Fat binaries, only native Mach-O
- Unlikely to work on 32 bit, don't have dinohardware; don't care.

Contributing
=======

Yes. Please to writing rest of web bigdata interface for clouds. Thx.

License
=======

None. BSD, whatever. This is a toy not a tool.


