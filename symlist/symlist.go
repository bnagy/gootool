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
// N_SECT (0xe)—The symbol is defined in the section number given in n_sect.
// ( if this bit is set in the type byte, it means the n_value will be an address )
const N_SECT = uint8(0x0e)
const REFERENCED_DYNAMICALLY = uint16(0x0010)
const S_SYMBOL_STUBS = uint32(0x08)
const S_LAZY_SYMBOL_POINTERS = uint32(0x07)

type SymType uint8

const (
	BBL  SymType = 0
	Stub SymType = 1
	Func SymType = 2
)

type SymEntry struct {
	Type SymType
	macho.Symbol
}

func (se *SymEntry) IsBBL() bool  { return se.Type == BBL }
func (se *SymEntry) IsFunc() bool { return se.Type == Func }
func (se *SymEntry) IsStub() bool { return se.Type == Stub }

type SymList struct {
	*list.List
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

	return 0, fmt.Errorf("Failed to find specified section.")

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

// Make a ghetto symbol "DB" and fill the linked list
// Map is for O(1) address->string lookups, list is for sym+offset lookups
func (sl *SymList) AddFn(sym macho.Symbol) {
	sl.doAdd(SymEntry{Func, sym})
}

func (sl *SymList) AddBBL(sym macho.Symbol) {
	sl.doAdd(SymEntry{BBL, sym})
}

func (sl *SymList) AddStub(sym macho.Symbol) {
	sl.doAdd(SymEntry{Stub, sym})
}

func (sl *SymList) Near(addr uint) (sym SymEntry, offset int, found bool) {
	for s := sl.Back(); s != nil; s = s.Prev() {
		this := s.Value.(SymEntry)
		if addr >= uint(this.Value) {
			return this, int(addr - uint(this.Value)), true
		}
	}
	return SymEntry{}, 0, false
}

func (sl *SymList) At(addr uint) (sym SymEntry, found bool) {
	sym, ok := sl.db[addr]
	return sym, ok
}

func (sl *SymList) Name(name string) (sym SymEntry, found bool) {
	for s := sl.Back(); s != nil; s = s.Prev() {
		this := s.Value.(SymEntry)
		if this.Name == name {
			return this, true
		}
	}
	return SymEntry{}, false
}

func (sl *SymList) Len() int {
	return len(sl.db)
}

func (sl *SymList) InText(addr uint64) bool {
	return addr >= sl.TextBase && addr < sl.TextBase+sl.TextSize
}

func NewSymList(mo *macho.File) (*SymList, error) {

	sl := &SymList{
		list.New(),
		make(map[uint]SymEntry),
		0,
		0,
	}

	// These are the real function syms
	for _, sym := range mo.Symtab.Syms {
		// TODO: MACH-O SYMBOLS, HOW DO THEY WORK?
		if sym.Sect == 1 && // text section
			sym.Type&N_SECT > 0 && // N_SECT ( internal or external )
			sym.Name != "" && // Don't know what these blank names are :/
			sym.Desc != REFERENCED_DYNAMICALLY { // Dynamic Symbols come next

			sl.AddFn(sym)

		}
	}

	textSection := mo.Section("__text")
	if textSection == nil {
		return &SymList{}, fmt.Errorf("Text section not found.")
	}

	sl.TextBase = textSection.Addr
	sl.TextSize = textSection.Size

	if sl.Len() == 0 {
		sl.AddFn(
			macho.Symbol{
				Name:  "<no_syms>_start",
				Type:  N_SECT,
				Sect:  uint8(1),
				Desc:  uint16(0),
				Value: sl.TextBase,
			},
		)
	}

	if len(mo.Dysymtab.IndirectSyms) == 0 {
		// No dynamic symbols, nothing more to do.
		return sl, nil
	}

	// Find the first section with the S_SYMBOL_STUBS flag set, since they
	// seem to have all kinds of names ( __stubs, __symbol_stub,
	// __symbol_stub1...)
	// TODO: Could there be more than one stub section? :/
	var stubs *macho.Section
	for _, sec := range mo.Sections {
		if sec.Flags&S_SYMBOL_STUBS == S_SYMBOL_STUBS {
			stubs = sec
			break
		}
	}
	if stubs == nil {
		return sl, fmt.Errorf("Symbol stubs couldn't be parsed, dynamic symbols not marked.")
	}

	stubBase := stubs.Addr
	stubSize, err := getStubSize(stubs, mo) // size of each stub
	if err != nil {
		return sl, fmt.Errorf("Symbol stubs couldn't be parsed, dynamic symbols not marked.")
	}

	var lsp *macho.Section
	for _, sec := range mo.Sections {
		if sec.Flags&S_LAZY_SYMBOL_POINTERS == S_LAZY_SYMBOL_POINTERS {
			lsp = sec
			break
		}
	}
	if lsp == nil {
		return sl, fmt.Errorf("Symbol stubs couldn't be parsed, dynamic symbols not marked.")
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
						Type:  N_SECT,
						Sect:  uint8(1),
						Desc:  uint16(0),
						Value: imm,
					},
				)
			} else {
				sl.AddBBL(
					macho.Symbol{
						Name:  fmt.Sprintf("loc_0x%x", imm),
						Type:  N_SECT,
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
						Type:  N_SECT,
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
