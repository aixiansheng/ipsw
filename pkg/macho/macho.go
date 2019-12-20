// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Mach-O header data structures
// Originally at:
// http://developer.apple.com/mac/library/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html (since deleted by Apply)
// Archived copy at:
// https://web.archive.org/web/20090819232456/http://developer.apple.com/documentation/DeveloperTools/Conceptual/MachORuntime/index.html
// For cloned PDF see:
// https://github.com/aidansteele/osx-abi-macho-file-format-reference

package macho

//go:generate stringer -type=platform,tool,diceKind -output macho_string.go

import (
	"strconv"
)

// A FileHeader represents a Mach-O file header.
type FileHeader struct {
	Magic  uint32
	Cpu    Cpu
	SubCpu uint32
	Type   Type
	Ncmd   uint32
	Cmdsz  uint32
	Flags  headerFlags
}

const (
	fileHeaderSize32 = 7 * 4
	fileHeaderSize64 = 8 * 4
)

const (
	Magic32  uint32 = 0xfeedface
	Magic64  uint32 = 0xfeedfacf
	MagicFat uint32 = 0xcafebabe
)

// A Type is the Mach-O file type, e.g. an object file, executable, or dynamic library.
type Type uint32

const (
	TypeObj                        Type = 1
	TypeExec                       Type = 2
	TypeDylib                      Type = 6
	TypeBundle                     Type = 8
	TypeNlistOutofsyncWithDyldinfo Type = 0x04000000 /* The external symbols
	   listed in the nlist symbol table do
	   not include all the symbols listed in
	   the dyld info. */
	TypeDylibInCache Type = 0x80000000 /* Only for use on dylibs. When this bit
	   is set, the dylib is part of the dyld
	   shared cache, rather than loose in
	   the filesystem. */
)

var typeStrings = []intName{
	{uint32(TypeObj), "Obj"},
	{uint32(TypeExec), "Exec"},
	{uint32(TypeDylib), "Dylib"},
	{uint32(TypeBundle), "Bundle"},
	{uint32(TypeNlistOutofsyncWithDyldinfo), "Nlist Out of sync With Dyldinfo"},
	{uint32(TypeDylibInCache), "Dylib in Cache"},
}

func (t Type) String() string   { return stringName(uint32(t), typeStrings, false) }
func (t Type) GoString() string { return stringName(uint32(t), typeStrings, true) }

// A Section32 is a 32-bit Mach-O section header.
type Section32 struct {
	Name     [16]byte
	Seg      [16]byte
	Addr     uint32
	Size     uint32
	Offset   uint32
	Align    uint32
	Reloff   uint32
	Nreloc   uint32
	Flags    uint32
	Reserve1 uint32
	Reserve2 uint32
}

// A Section64 is a 64-bit Mach-O section header.
type Section64 struct {
	Name     [16]byte
	Seg      [16]byte
	Addr     uint64
	Size     uint64
	Offset   uint32
	Align    uint32
	Reloff   uint32
	Nreloc   uint32
	Flags    uint32
	Reserve1 uint32
	Reserve2 uint32
	Reserve3 uint32
}

// An Nlist32 is a Mach-O 32-bit symbol table entry.
type Nlist32 struct {
	Name  uint32
	Type  uint8
	Sect  uint8
	Desc  uint16
	Value uint32
}

// An Nlist64 is a Mach-O 64-bit symbol table entry.
type Nlist64 struct {
	Name  uint32
	Type  uint8
	Sect  uint8
	Desc  uint16
	Value uint64
}

// Regs386 is the Mach-O 386 register structure.
type Regs386 struct {
	AX    uint32
	BX    uint32
	CX    uint32
	DX    uint32
	DI    uint32
	SI    uint32
	BP    uint32
	SP    uint32
	SS    uint32
	FLAGS uint32
	IP    uint32
	CS    uint32
	DS    uint32
	ES    uint32
	FS    uint32
	GS    uint32
}

// RegsAMD64 is the Mach-O AMD64 register structure.
type RegsAMD64 struct {
	AX    uint64
	BX    uint64
	CX    uint64
	DX    uint64
	DI    uint64
	SI    uint64
	BP    uint64
	SP    uint64
	R8    uint64
	R9    uint64
	R10   uint64
	R11   uint64
	R12   uint64
	R13   uint64
	R14   uint64
	R15   uint64
	IP    uint64
	FLAGS uint64
	CS    uint64
	FS    uint64
	GS    uint64
}

type intName struct {
	i uint32
	s string
}

func stringName(i uint32, names []intName, goSyntax bool) string {
	for _, n := range names {
		if n.i == i {
			if goSyntax {
				return "macho." + n.s
			}
			return n.s
		}
	}
	return strconv.FormatUint(uint64(i), 10)
}