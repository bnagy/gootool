package symlist

import "container/list"
import "debug/macho"

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

func NewSymList() *SymList {
	return &SymList{
		list.New(),
		make(map[uint]macho.Symbol),
	}
}
