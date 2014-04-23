package symlist

import (
	"bytes"
	"container/list"
	"debug/macho"
	"encoding/binary"
	"fmt"
)

// https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-BAJFFCGF
// N_SECT (0xe)—The symbol is defined in the section number given in n_sect.
// ( if this bit is set in the type byte, it means the n_value will be an address )
const N_SECT = uint8(0x0e)
const REFERENCED_DYNAMICALLY = uint16(0x0010)

type SymList struct {
	*list.List
	db map[uint]macho.Symbol
}

func cstring(b []byte) string {
	var i int
	for i = 0; i < len(b) && b[i] != 0; i++ {
	}
	return string(b[0:i])
}

// Find the "Size of Stubs" value in the specified section. Have to do this by
// parsings the raw load commands, because macho.Section does not expose any
// of the reserved flags
func getStubSize(stubSect *macho.Section, mo *macho.File) (uint32, error) {
	// Copied and stripped down from the macho source. Error handling removed,
	// because macho already did it.

	bo := mo.ByteOrder
	for _, l := range mo.Loads {

		dat := l.Raw()
		// Each load command begins with uint32 command and length.
		cmd, siz := macho.LoadCmd(bo.Uint32(dat[0:4])), bo.Uint32(dat[4:8])
		cmddat := dat[0:siz]

		switch cmd {

		default:
			continue

		case macho.LoadCmdSegment:
			var seg32 macho.Segment32
			b := bytes.NewBuffer(cmddat)
			if err := binary.Read(b, bo, &seg32); err != nil {
				return 0, err
			}
			if cstring(seg32.Name[0:]) != stubSect.Seg {
				continue
			}
			for i := uint32(0); i < seg32.Nsect; i++ {
				var sh32 macho.Section32
				if err := binary.Read(b, bo, &sh32); err != nil {
					return 0, err
				}
				if cstring(sh32.Name[0:]) != stubSect.Name {
					continue
				}
				return sh32.Reserve2, nil
			}

		case macho.LoadCmdSegment64:
			var seg64 macho.Segment64
			b := bytes.NewBuffer(cmddat)
			if err := binary.Read(b, bo, &seg64); err != nil {
				return 0, err
			}
			if cstring(seg64.Name[0:]) != stubSect.Seg {
				continue
			}
			for i := uint32(0); i < seg64.Nsect; i++ {
				var sh64 macho.Section64
				if err := binary.Read(b, bo, &sh64); err != nil {
					return 0, err
				}
				if cstring(sh64.Name[0:]) != stubSect.Name {
					continue
				}
				return sh64.Reserve2, nil
			}

		}
	}

	return 0, fmt.Errorf("Failed to find specified section.")

}

// Make a ghetto symbol "DB" and fill the linked list
// Map is for O(1) address->string lookups, list is for sym+offset lookups
func (sl *SymList) Add(sym macho.Symbol) {

	sl.db[uint(sym.Value)] = sym

	for s := sl.Back(); s != nil; s = s.Prev() {
		this := s.Value.(macho.Symbol)
		if sym.Value > this.Value {
			sl.InsertAfter(sym, s)
			return
		}
	}
	// Wasn't inserted after anything, must be lowest value
	sl.PushFront(sym)
}

func (sl *SymList) Near(addr uint64) (sym macho.Symbol, offset int, found bool) {
	for s := sl.Back(); s != nil; s = s.Prev() {
		this := s.Value.(macho.Symbol)
		if addr >= this.Value {
			return this, int(addr - this.Value), true
		}
	}
	return macho.Symbol{}, 0, false
}

func (sl *SymList) At(addr uint) (sym macho.Symbol, found bool) {
	sym, ok := sl.db[addr]
	return sym, ok
}

func NewSymList(mo *macho.File) (*SymList, error) {

	sl := &SymList{
		list.New(),
		make(map[uint]macho.Symbol),
	}

	for _, sym := range mo.Symtab.Syms {
		// TODO: MACH-O SYMBOLS, HOW DO THEY WORK?
		if sym.Sect == 1 && // text section
			sym.Type&N_SECT > 0 && // N_SECT ( internal or external )
			sym.Name != "" && // Don't know what these blank names are :/
			sym.Desc != REFERENCED_DYNAMICALLY { // Dynamic Symbols come next

			sl.Add(sym)

		}
	}

	textSection := mo.Section("__text")
	if textSection == nil {
		return &SymList{}, fmt.Errorf("Text section not found.")
	}

	if len(mo.Dysymtab.IndirectSyms) == 0 {
		// No dynamic symbols, nothing more to do.
		return sl, nil
	}

	// TODO: Other possible names? I've only looked at a few binaries...
	stubs := mo.Section("__stubs")
	if stubs == nil {
		stubs = mo.Section("__symbol_stub")
	}
	if stubs == nil {
		return sl, fmt.Errorf("Symbol stubs not found, dynamic symbols not marked.")
	}

	stubBase := stubs.Addr
	stubSize, err := getStubSize(stubs, mo) // size of each stub
	if err != nil {
		return sl, fmt.Errorf("Symbol stubs couldn't be parsed, dynamic symbols not marked.")
	}

	lsp := mo.Section("__la_symbol_ptr")

	for i, dsIdx := range mo.Dysymtab.IndirectSyms {

		// The size of the lazy symbol pointer section / its alignment is the
		// number of lazy symbols for __TEXT,__text. The Align value is a
		// binary exponent.
		if uint64(i) >= lsp.Size/(1<<lsp.Align) {
			break
		}

		// The Go IndirectSyms slice is composed of indicies into the real
		// Symtab. The first clump are ( I hope ) the lazy symbols for the
		// text section, followed by the got, which I don't mark up, yet.
		if _, exists := sl.At(uint(uint32(i)*stubSize) + uint(stubBase)); !exists {
			sl.Add(
				macho.Symbol{
					Name:  fmt.Sprintf("STUB%s", mo.Symtab.Syms[dsIdx].Name),
					Type:  N_SECT,
					Sect:  uint8(1),
					Desc:  uint16(0),
					Value: uint64(uint32(i)*stubSize) + stubBase,
				},
			)
		}
	}

	return sl, nil

}
