package symlist

import (
	"bytes"
	"container/list"
	"debug/macho"
	"encoding/binary"
	"fmt"
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/util"
)

// https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-BAJFFCGF
const (
	NSect                 = uint8(0x0e)
	ReferencedDynamically = uint16(0x0010)
	SymbolStubs           = uint32(0x08)
	LazySymbolPointers    = uint32(0x07)
	CStringLiterals       = uint32(0x02)
)

// SymType can be BBL, Func or Stub
type SymType uint8

// Available symbol types:
const (
	BBL  SymType = 0 // Basic Block ( inside a Func )
	Stub SymType = 1 // Dynamic symbol stub
	Func SymType = 2 // Function head in _text section
)

// SymEntry is a simple wrapper for macho.Symbol adding a Type to help with
// graphing
type SymEntry struct {
	Type SymType
	macho.Symbol
}

// CString holds the contents of the __cstrings section in the macho binary,
// plus basic metadata
type CString struct {
	Base uint64
	Size uint64
	Raw  []byte
}

// IsBBL returns true is the given symbol is a BBL
func (se *SymEntry) IsBBL() bool { return se.Type == BBL }

// IsFunc returns true is the given symbol is a Func
func (se *SymEntry) IsFunc() bool { return se.Type == Func }

// IsStub returns true is the given symbol is a Stub
func (se *SymEntry) IsStub() bool { return se.Type == Stub }

// SymList is intended to be used like a linked list, but it also contains
// CStrings and some metadata about the __text section
type SymList struct {
	*list.List
	CStrings CString
	db       map[uint]SymEntry
	TextBase uint64
	TextSize uint64
}

func cstring(b []byte) string {
	var i int
	for i = 0; i < len(b) && b[i] != 0; i++ {
	}
	return string(b[0:i])
}

// Find the "Size of Stubs" value in the specified section. Have to do this by
// parsing the raw load commands, because macho.Section does not expose any
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

	return 0, fmt.Errorf("failed to find specified section")

}

func (sl *SymList) doAdd(sym SymEntry) {

	if _, exists := sl.db[uint(sym.Value)]; exists {
		return
	}

	sl.db[uint(sym.Value)] = sym

	for s := sl.Back(); s != nil; s = s.Prev() {
		this := s.Value.(SymEntry)
		if sym.Value > this.Value {
			sl.InsertAfter(sym, s)
			return
		}
	}
	// Wasn't inserted after anything, must be lowest value
	sl.PushFront(sym)
}

// AddFn adds a symbol as a Func SymType
func (sl *SymList) AddFn(sym macho.Symbol) {
	sl.doAdd(SymEntry{Func, sym})
}

// AddBBL adds a symbol as a BBL SymType
func (sl *SymList) AddBBL(sym macho.Symbol) {
	sl.doAdd(SymEntry{BBL, sym})
}

// AddStub adds a symbol as a Stub SymType
func (sl *SymList) AddStub(sym macho.Symbol) {
	sl.doAdd(SymEntry{Stub, sym})
}

// Near returns a symbol, offset pair, if there is a neaby symbol for the
// given address
func (sl *SymList) Near(addr uint) (sym SymEntry, offset int, found bool) {
	for s := sl.Back(); s != nil; s = s.Prev() {
		this := s.Value.(SymEntry)
		if addr >= uint(this.Value) {
			return this, int(addr - uint(this.Value)), true
		}
	}
	return SymEntry{}, 0, false
}

// At returns a symbol iff there is an exact match
func (sl *SymList) At(addr uint) (sym SymEntry, found bool) {
	sym, ok := sl.db[addr]
	return sym, ok
}

// Name returns the symbol entry for a given string
func (sl *SymList) Name(name string) (sym SymEntry, found bool) {
	for s := sl.Back(); s != nil; s = s.Prev() {
		this := s.Value.(SymEntry)
		if this.Name == name {
			return this, true
		}
	}
	return SymEntry{}, false
}

// Len is a utility method, since the list is promoted, and len(list) can't be
// used
func (sl *SymList) Len() int {
	return len(sl.db)
}

// InText is sugar to check if an address is within the text segment
func (sl *SymList) InText(addr uint64) bool {
	return addr >= sl.TextBase && addr < sl.TextBase+sl.TextSize
}

func secByFlag(mo *macho.File, flag uint32) (*macho.Section, error) {
	var sec *macho.Section
	for _, s := range mo.Sections {
		if s.Flags&flag == flag {
			sec = s
			break
		}
	}
	if sec == nil {
		return sec, fmt.Errorf("symbol stubs couldn't be parsed, dynamic symbols not marked")
	}
	return sec, nil
}

// NewSymList will create a SymList from a given *macho.File
// - Add symbols for all exported functions
// - Tries to add Stubs for any dynamic symbols
// - Parses and adds the CStrings struct from the _cstrings section
func NewSymList(mo *macho.File) (*SymList, error) {

	sl := &SymList{
		list.New(),
		CString{},
		make(map[uint]SymEntry),
		0,
		0,
	}

	// These are the real function syms
	for _, sym := range mo.Symtab.Syms {
		// TODO: MACH-O SYMBOLS, HOW DO THEY WORK?
		if sym.Sect == 1 && // text section
			sym.Type&NSect == NSect &&
			sym.Name != "" && // Don't know what these blank names are :/
			sym.Desc != ReferencedDynamically { // Dynamic Symbols come next

			sl.AddFn(sym)

		}
	}

	textSection := mo.Section("__text")
	if textSection == nil {
		return &SymList{}, fmt.Errorf("text section not found")
	}

	sl.TextBase = textSection.Addr
	sl.TextSize = textSection.Size

	if sl.Len() == 0 {
		sl.AddFn(
			macho.Symbol{
				Name:  "<no_syms>_start",
				Type:  NSect,
				Sect:  uint8(1),
				Desc:  uint16(0),
				Value: sl.TextBase,
			},
		)
	}

	cs, err := secByFlag(mo, CStringLiterals)
	if err == nil {
		raw, _ := cs.Data()
		sl.CStrings = CString{
			Base: cs.Addr,
			Size: cs.Size,
			Raw:  raw,
		}
	}

	if len(mo.Dysymtab.IndirectSyms) == 0 {
		// No dynamic symbols, nothing more to do.
		return sl, nil
	}

	// Find the first section with the SymbolStubs flag set, since they
	// seem to have all kinds of names ( __stubs, __symbol_stub,
	// __symbol_stub1...)
	// TODO: Could there be more than one stub section? :/
	stubs, err := secByFlag(mo, SymbolStubs)
	if err != nil {
		return sl, err
	}

	stubBase := stubs.Addr
	stubSize, err := getStubSize(stubs, mo) // size of each stub
	if err != nil {
		return sl, fmt.Errorf("symbol stubs couldn't be parsed, dynamic symbols not marked")
	}

	lsp, err := secByFlag(mo, LazySymbolPointers)
	if err != nil {
		return sl, err
	}

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
			sl.AddStub(
				macho.Symbol{
					Name:  fmt.Sprintf("STUB%s", mo.Symtab.Syms[dsIdx].Name),
					Type:  NSect,
					Sect:  uint8(1),
					Desc:  uint16(0),
					Value: uint64(uint32(i)*stubSize) + stubBase,
				},
			)
		}
	}

	return sl, nil

}

// SymboliseBBLs is a disassembly callback for use by gootool.go. It will
// attempt to infer BBLs and add symbols for them
func (sl *SymList) SymboliseBBLs(insn cs.Instruction) error {
	if util.IsJmpCallImm(insn) {

		// Add a BBL head symbol for the target of any jmp or call with an
		// immediate operand
		imm := uint64(insn.X86.Operands[0].Imm)
		if _, exists := sl.At(uint(imm)); !exists && sl.InText(imm) {
			if util.IsCallImm(insn) {
				sl.AddFn(
					macho.Symbol{
						Name:  fmt.Sprintf("func_0x%x", imm),
						Type:  NSect,
						Sect:  uint8(1),
						Desc:  uint16(0),
						Value: imm,
					},
				)
			} else {
				sl.AddBBL(
					macho.Symbol{
						Name:  fmt.Sprintf("loc_0x%x", imm),
						Type:  NSect,
						Sect:  uint8(1),
						Desc:  uint16(0),
						Value: imm,
					},
				)
			}

		}
		// For any kind of JMP ( but not call ), add a symbol for the next
		// instruction, since it needs to become a BBL head
		if util.IsJmpImm(insn) {
			if _, exists := sl.At(insn.Address + insn.Size); !exists && sl.InText(uint64(insn.Address+insn.Size)) {
				sl.AddBBL(
					macho.Symbol{
						Name:  fmt.Sprintf("loc_0x%x", insn.Address+insn.Size),
						Type:  NSect,
						Sect:  uint8(1),
						Desc:  uint16(0),
						Value: uint64(insn.Address + insn.Size),
					},
				)
			}
		}
	}

	return nil
}
