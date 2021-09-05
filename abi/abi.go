package abi

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"io"
	"strings"
)

var (
	// ErrCompileUnitNotFound is returned when the dwarf debug doesn't have a compile
	// unit
	ErrCompileUnitNotFound = errors.New("failed to find compile unit")
	// ErrProducerString is returned when the dwarf compile unit producer attribute
	// string is the wrong type
	ErrProducerString = errors.New("DWARF producer string incorrect type")
)

// Regs returns true if passing arguments in registers is enabled
// for the target executable
func Regs(f io.ReaderAt) (bool, error) {
	file, err := elf.NewFile(f)
	if err != nil {
		return false, err
	}
	dbg, err := file.DWARF()
	if err != nil {
		return false, err
	}

	reader := dbg.Reader()

	compileUnit, err := func() (*dwarf.Entry, error) {
		for {
			entry, err := reader.Next()
			if entry == nil || err == io.EOF {
				return nil, ErrCompileUnitNotFound
			}
			if err != nil {
				return nil, err
			}
			if entry.Tag == dwarf.TagCompileUnit {
				return entry, nil
			}
		}
	}()

	if err != nil {
		return false, err
	}

	for _, field := range compileUnit.Field {
		if field.Attr == dwarf.AttrProducer {
			producer, ok := field.Val.(string)
			if !ok {
				return false, ErrProducerString
			}
			return strings.HasSuffix(producer, "; regabi"), nil
		}
	}
	return false, nil
}
