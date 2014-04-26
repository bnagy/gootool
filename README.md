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
_fuzzy_hash_buf Len: 13 Tail: 0 Edges: T:0x1000040be F:0x100003e94 A:0x0
loc_0x100003e94 Len: 2 Tail: 0 Edges: T:0x1000040be F:0x100003e9d A:0x0
loc_0x100003e9d Len: 4 Tail: 0 Edges: T:0x1000040be F:0x100003eb0 A:0x0 Calls ==> [ STUB_malloc ]
loc_0x100003eb0 Len: 7 Tail: 0 Edges: T:0x100003f02 F:0x100003ec9 A:0x0 Calls ==> [ STUB_malloc ]
loc_0x100003ec9 Len: 3 Tail: 0 Edges: T:0x100003ee1 F:0x100003ed9 A:0x0
loc_0x100003ed9 Len: 2 Tail: 0 Edges: T:0x0 F:0x0 A:0x100003f02
loc_0x100003ee1 Len: 2 Tail: 0 Edges: T:0x0 F:0x0 A:0x100003ef0
loc_0x100003ef0 Len: 5 Tail: 0 Edges: T:0x100003ef0 F:0x100003efe A:0x0
loc_0x100003efe Len: 1 Tail: 0 Edges: T:0x0 F:0x0 A:0x100003f02
loc_0x100003f02 Len: 4 Tail: 0 Edges: T:0x0 F:0x0 A:0x100003f17
loc_0x100003f0e Len: 1 Tail: 0 Edges: T:0x0 F:0x0 A:0x100003f10
loc_0x100003f10 Len: 2 Tail: 0 Edges: T:0x0 F:0x0 A:0x100003f17
loc_0x100003f17 Len: 40 Tail: 0 Edges: T:0x100004016 F:0x10000400e A:0x0 Calls ==> [ STUB___snprintf_chk  STUB_strlen  _ss_engine ]
loc_0x10000400e Len: 2 Tail: 0 Edges: T:0x0 F:0x0 A:0x100004023
loc_0x100004016 Len: 2 Tail: 0 Edges: T:0x10000400e F:0x10000401d A:0x0
loc_0x10000401d Len: 2 Tail: 0 Edges: T:0x0 F:0x0 A:0x100004023
loc_0x100004023 Len: 2 Tail: 0 Edges: T:0x100004059 F:0x10000402a A:0x0
loc_0x10000402a Len: 12 Tail: 0 Edges: T:0x0 F:0x0 A:0x100004059
loc_0x100004059 Len: 12 Tail: 0 Edges: T:0x100003f10 F:0x100004094 A:0x0 Calls ==> [ STUB___strcat_chk ]
loc_0x100004094 Len: 7 Tail: 0 Edges: T:0x1000040b2 F:0x1000040ad A:0x0 Calls ==> [ STUB_strncpy ]
loc_0x1000040ad Len: 1 Tail: 0 Edges: T:0x0 F:0x0 A:0x1000040b2 Calls ==> [ STUB_free ]
loc_0x1000040b2 Len: 4 Tail: 0 Edges: T:0x0 F:0x0 A:0x1000040c3 Calls ==> [ STUB_free ]
loc_0x1000040be Len: 1 Tail: 0 Edges: T:0x0 F:0x0 A:0x1000040c3
loc_0x1000040c3 Len: 8 Tail: 2 Edges: T:0x0 F:0x0 A:0x0 [terminal]
_fuzzy_hash_filename Len: 6 Tail: 0 Edges: T:0x100004121 F:0x1000040ec A:0x0
loc_0x1000040ec Len: 3 Tail: 0 Edges: T:0x100004121 F:0x1000040f4 A:0x0
loc_0x1000040f4 Len: 4 Tail: 0 Edges: T:0x100004121 F:0x100004105 A:0x0 Calls ==> [ STUB_fopen ]
loc_0x100004105 Len: 9 Tail: 0 Edges: T:0x0 F:0x0 A:0x100004126 Calls ==> [ _fuzzy_hash_file  STUB_fclose ]
loc_0x100004121 Len: 1 Tail: 0 Edges: T:0x0 F:0x0 A:0x100004126
loc_0x100004126 Len: 4 Tail: 5 Edges: T:0x0 F:0x0 A:0x0 [terminal]
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


