gootool
=======

Silly PoC of a limited otool clone based on the capstone disassembly lib

Eventually aiming to produce silly graph output with D3.js

This is a toy, not a tool.

TODO:
=======

Next step is to code the CFG architecture and write a transformer for each BBL to a Node struct with edges and whatever other metadata. After that, add the D3 html template code, CSS, etc, then write a transformer for the CFG nodes to the required raw data as JSON.

BUGS
=======

This is definitely going to fail spectacularly on any kind of obfuscated binary of any kind. Also, Go's macho parser doesn't seem to recognise some magic values, so some binaries just won't parse at all.

Contributing
=======

As if.


