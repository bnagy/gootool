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

```
(0x10000eac0): _needfree Len: 10 Tail: 0 Edges:  T: loc_0x10000eaee F: loc_0x10000eae3
	0x10000eac0: 55                       push        rbp
	0x10000eac1: 4889e5                   mov         rbp, rsp
	0x10000eac4: 4883ec20                 sub         rsp, 0x20
	0x10000eac8: 48897df0                 mov         qword ptr [rbp + 0xfffffffffffffff0], rdi
	0x10000eacc: 8975ec                   mov         dword ptr [rbp + 0xffffffffffffffec], esi
	0x10000eacf: 488b7df0                 mov         rdi, qword ptr [rbp + 0xfffffffffffffff0]
	0x10000ead3: 488b7f20                 mov         rdi, qword ptr [rdi + 0x20]
	0x10000ead7: 8b7718                   mov         esi, dword ptr [rdi + 0x18]
	0x10000eada: 3b75ec                   cmp         esi, dword ptr [rbp + 0xffffffffffffffec]
	0x10000eadd: 0f8c0b000000             jl          loc_0x10000eaee
loc_0x10000eaee Len: 4 Tail: 0 Edges:  T: loc_0x10000eb0d F: loc_0x10000eb02 Calls ==> [ _makenextfile ]
	0x10000eaee: 488b7df0                 mov         rdi, qword ptr [rbp + 0xfffffffffffffff0]
	0x10000eaf2: e8a9feffff               call        _makenextfile
	0x10000eaf7: 3d00000000               cmp         eax, 0
	0x10000eafc: 0f840b000000             je          loc_0x10000eb0d
loc_0x10000eae3 Len: 3 Tail: 0 Edges:  A: loc_0x10000eb14
	0x10000eae3: 8b45ec                   mov         eax, dword ptr [rbp + 0xffffffffffffffec]
	0x10000eae6: 8945fc                   mov         dword ptr [rbp + 0xfffffffffffffffc], eax
	0x10000eae9: e926000000               jmp         loc_0x10000eb14
loc_0x10000eb14 Len: 4 Tail: 1 Edges:  [terminal]
	0x10000eb14: 8b45fc                   mov         eax, dword ptr [rbp + 0xfffffffffffffffc]
	0x10000eb17: 4883c420                 add         rsp, 0x20
	0x10000eb1b: 5d                       pop         rbp
	0x10000eb1c: c3                       ret
loc_0x10000eb0d Len: 1 Tail: 0 Edges:  A: loc_0x10000eb14
	0x10000eb0d: c745fc00000000           mov         dword ptr [rbp + 0xfffffffffffffffc], 0
loc_0x10000eb02 Len: 3 Tail: 0 Edges:  A: loc_0x10000eb14
	0x10000eb02: 8b45ec                   mov         eax, dword ptr [rbp + 0xffffffffffffffec]
	0x10000eb05: 8945fc                   mov         dword ptr [rbp + 0xfffffffffffffffc], eax
	0x10000eb08: e907000000               jmp         loc_0x10000eb14

ALL _needfree calls => [ _makenextfile  ]
```

BUGS
=======

This is definitely going to fail spectacularly on any kind of obfuscated binary. It's also going to be pretty crappy without symbols, and may well completely break.

- dead code detection at the end of blocks is pretty crappy
- Doesn't work on Fat binaries, only native Mach-O
- Unlikely to work on 32 bit, don't have dinohardware; don't care.

Contributing
=======

Yes. Please to writing rest of web bigdata interface for clouds. Thx.

License
=======

None. BSD, whatever. This is a toy not a tool.


