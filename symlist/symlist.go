package symlist

import (
	"container/list"
	"debug/macho"
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

	// TODO: Other possible names? I've only looked at a few binaries...
	stubs := mo.Section("__stubs")
	if stubs == nil {
		stubs = mo.Section("__symbol_stub")
	}
	if stubs == nil {
		return sl, fmt.Errorf("Symbol stubs not found, dynamic symbols not marked.")
	}
	stubBase := stubs.Addr

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
		if _, exists := sl.At(uint(i*6) + uint(stubBase)); !exists {
			sl.Add(
				macho.Symbol{
					Name:  fmt.Sprintf("STUB%s", mo.Symtab.Syms[dsIdx].Name),
					Type:  N_SECT,
					Sect:  uint8(1),
					Desc:  uint16(0),
					Value: uint64(i)*6 + stubBase,
				},
			)
		}
	}

	return sl, nil

}
