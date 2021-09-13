package abi

import (
	"debug/elf"
	"errors"
	"io"

	"golang.org/x/arch/x86/x86asm"
)

var (
	ErrMemEqualNotFound = errors.New("runtime.memequal0 not found")
	ErrWrongInstruction = errors.New("MOVL not first instruction of runtime.memequal0")
)

// Regs returns true if passing arguments in registers is enabled
// for the target executable
func Regs(r io.ReaderAt) (bool, error) {
	// To cope with an absence of DWARF symbols in commonly used
	// programs written in golang (dockerd etc etc), do something
	// a little hacky to work out the calling convention.
	//
	// runtime.memequal0 is very short and reveals which calling
	// convention is used
	// e.g for register based
	// TEXT runtime.memequal0(SB) /usr/local/go/src/runtime/alg.go
	//  alg.go:201		0x4023a0		b801000000		MOVL $0x1, AX
	//  alg.go:201		0x4023a5		c3				RET
	//
	// for stack based (from dockerd)
	// TEXT runtime.memequal0(SB)
	//	:0			0x1e49b20		c644241801		MOVB $0x1, 0x18(SP)
	//	:0			0x1e49b25		c3			RET
	// (note the lack of symbols)

	file, err := elf.NewFile(r)
	if err != nil {
		return false, err
	}

	symbolName := "runtime.memequal0"

	symbols, err := file.Symbols()
	if err != nil {
		return false, err
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
		return false, ErrMemEqualNotFound
	}

	section := file.Sections[symbol.Section]

	text, err := section.Data()
	if err != nil {
		return false, err
	}

	start := symbol.Value - section.Addr
	end := start + symbol.Size

	function := text[start:end]

	inst, err := x86asm.Decode(function, 64)
	if err != nil {
		return false, err
	}

	if inst.Op != x86asm.MOV {
		return false, ErrWrongInstruction
	}
	return (inst.Args[0].String() == "EAX" && inst.Args[1].String() == "0x1"), nil
}
