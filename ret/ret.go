package ret

import (
	"debug/elf"
	"errors"
	"io"

	"golang.org/x/arch/x86/x86asm"
)

var (
	// ErrSymbolNotFound returned when the specified symbol is not located
	// in the target ELF file
	ErrSymbolNotFound = errors.New("symbol not found")
	// ErrNoRetFound is returned when no RET instructions are found in
	// the function
	ErrNoRetFound = errors.New("no RET instructions found")
)

// FindOffsets finds all the offsets within a given function
// where RET instructions are found
func FindOffsets(r io.ReaderAt, symbolName string) ([]int, error) {
	file, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	symbols, err := file.Symbols()
	if err != nil {
		return nil, err
	}

	var symbol elf.Symbol
	found := false
	for _, s := range symbols {
		if s.Name == symbolName {
			symbol = s
			found = true
			break
		}
	}
	if !found {
		return nil, ErrSymbolNotFound
	}

	section := file.Sections[symbol.Section]

	text, err := section.Data()
	if err != nil {
		return nil, err
	}

	start := symbol.Value - section.Addr
	end := start + symbol.Size

	function := text[start:end]
	returns := []int{}

	for i := 0; i < len(function); {
		inst, err := x86asm.Decode(function[i:], 64)
		if err != nil {
			return nil, err
		}
		if inst.Op == x86asm.RET {
			returns = append(returns, i)
		}
		i += inst.Len
	}
	if len(returns) == 0 {
		return returns, ErrNoRetFound
	}

	return returns, nil
}
