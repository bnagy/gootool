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
_log_get_prefix Len: 4 Tail: 0 Edges: T:0x0 F:0x0 A:0xa1ee9 Calls ==> [ loc_0xa1ee9 ]
loc_0xa1ee9 Len: 3 Tail: 0 Edges: T:0xa1f65 F:0xa1ef0 A:0x0
loc_0xa1ef0 Len: 6 Tail: 0 Edges: T:0xa1f14 F:0xa1f05 A:0x0
loc_0xa1f05 Len: 6 Tail: 0 Edges: T:0x0 F:0x0 A:0xa1f14
loc_0xa1f14 Len: 4 Tail: 0 Edges: T:0xa1f2f F:0xa1f20 A:0x0
loc_0xa1f20 Len: 6 Tail: 0 Edges: T:0x0 F:0x0 A:0xa1f2f
loc_0xa1f2f Len: 4 Tail: 0 Edges: T:0xa1f4a F:0xa1f3b A:0x0
loc_0xa1f3b Len: 6 Tail: 0 Edges: T:0x0 F:0x0 A:0xa1f4a
loc_0xa1f4a Len: 4 Tail: 0 Edges: T:0xa1f65 F:0xa1f56 A:0x0
loc_0xa1f56 Len: 6 Tail: 0 Edges: T:0x0 F:0x0 A:0xa1f65
loc_0xa1f65 Len: 3 Tail: 0 Edges: T:0x0 F:0x0 A:0x0 [terminal]
_log_test_fd Len: 5 Tail: 0 Edges: T:0x0 F:0x0 A:0xa1f79 Calls ==> [ loc_0xa1f79 ]
loc_0xa1f79 Len: 5 Tail: 0 Edges: T:0xa1fb0 F:0xa1f86 A:0x0
loc_0xa1f86 Len: 7 Tail: 0 Edges: T:0xa1fb0 F:0xa1f9f A:0x0 Calls ==> [ STUB_fileno ]
loc_0xa1f9f Len: 3 Tail: 0 Edges: T:0xa1fb0 F:0xa1fa7 A:0x0
loc_0xa1fa7 Len: 2 Tail: 0 Edges: T:0x0 F:0x0 A:0xa1fda
loc_0xa1fb0 Len: 4 Tail: 0 Edges: T:0xa1fd3 F:0xa1fbd A:0x0
loc_0xa1fbd Len: 4 Tail: 0 Edges: T:0xa1fd3 F:0xa1fca A:0x0
loc_0xa1fca Len: 2 Tail: 0 Edges: T:0x0 F:0x0 A:0xa1fda
loc_0xa1fd3 Len: 1 Tail: 0 Edges: T:0x0 F:0x0 A:0xa1fda
loc_0xa1fda Len: 5 Tail: 0 Edges: T:0x0 F:0x0 A:0x0 [terminal]
_log_get_fd Len: 5 Tail: 0 Edges: T:0x0 F:0x0 A:0xa1fef Calls ==> [ loc_0xa1fef ]
loc_0xa1fef Len: 5 Tail: 0 Edges: T:0xa2009 F:0xa1ffc A:0x0
loc_0xa1ffc Len: 4 Tail: 0 Edges: T:0x0 F:0x0 A:0xa2016
loc_0xa2009 Len: 4 Tail: 0 Edges: T:0x0 F:0x0 A:0xa2016
loc_0xa2016 Len: 7 Tail: 0 Edges: T:0x0 F:0x0 A:0x0 Calls ==> [ STUB_fileno ] [terminal]
_log_get_stream Len: 4 Tail: 0 Edges: T:0x0 F:0x0 A:0xa2032 Calls ==> [ loc_0xa2032 ]
loc_0xa2032 Len: 5 Tail: 0 Edges: T:0xa204c F:0xa203f A:0x0
loc_0xa203f Len: 4 Tail: 0 Edges: T:0x0 F:0x0 A:0xa2059
loc_0xa204c Len: 4 Tail: 0 Edges: T:0x0 F:0x0 A:0xa2059
loc_0xa2059 Len: 3 Tail: 0 Edges: T:0x0 F:0x0 A:0x0 [terminal]
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


