package goid

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"io"
)

var (
	// ErrNotFound returned with runtime.g is not found in the DWARF debug symbols
	// for the target binary
	ErrNotFound = errors.New("runtime.g not found")
	// ErrNoFields is returned if runtime.g is found by there is no debug information
	// for the fields
	ErrNoFields = errors.New("runtime.g has no fields")
	// ErrFieldNotFound is returned if the goid field debug is not found
	ErrFieldNotFound = errors.New("field goid not found")
)

// Offset will locate the offset of the "goid" field in the struct runtime.g
func Offset(f io.ReaderAt) (int64, error) {
	file, err := elf.NewFile(f)
	if err != nil {
		return 0, err
	}
	dbg, err := file.DWARF()
	if err != nil {
		panic(err)
	}

	reader := dbg.Reader()

	runtimeg, err := func() (*dwarf.Entry, error) {
		for {
			entry, err := reader.Next()
			if err != nil {
				if err == io.EOF {
					return nil, ErrNotFound
				}
				return nil, err
			}
			if entry.Tag == dwarf.TagStructType {
				for _, field := range entry.Field {
					if field.Attr == dwarf.AttrName && field.Val == "runtime.g" {
						return entry, nil
					}
				}
			}
		}
	}()

	if err != nil {
		return 0, err
	}

	if !runtimeg.Children {
		return 0, ErrNoFields
	}

	// search runtimeg children for goid field
	found := false
	var goid int64
	for !found {
		entry, err := reader.Next()
		if err != nil {
			if err == io.EOF {
				return 0, ErrFieldNotFound
			}
			return 0, err
		}

		if entry.Tag != dwarf.TagMember {
			break
		}

		for _, field := range entry.Field {
			if field.Attr == dwarf.AttrName {
				if field.Val == "goid" {
					found = true
				} else {
					break
				}
			}
			if field.Attr == dwarf.AttrDataMemberLoc {
				tmp, ok := field.Val.(int64)
				if ok {
					goid = tmp
				}
			}
		}
	}

	if !found {
		return 0, ErrFieldNotFound
	}

	return goid, nil
}
