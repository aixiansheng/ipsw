package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/pkg/errors"
)

type optFlags uint32

const (
	isProduction              optFlags = (1 << 0) // never set in development cache
	noMissingWeakSuperclasses optFlags = (1 << 1) // never set in development cache
)

// Optimization structure
type Optimization struct {
	Version           uint32
	Flags             optFlags
	SelectorOptOffset int32
	HeaderOptRoOffset int32
	ClassOptOffset    int32
	// _                 uint32
	ProtocolOptOffset int32
	HeaderOptRwOffset int32
}

func (o Optimization) isPointerAligned() bool {
	return (binary.Size(o) % 8) == 0
}

func (o Optimization) String() string {
	return fmt.Sprintf(
		"Version           = %d\n"+
			"Flags             = %d\n"+
			"SelectorOptOffset = %016X\n"+
			"HeaderOptRoOffset = %016X\n"+
			"ClassOptOffset    = %016X\n"+
			"ProtocolOptOffset = %016X\n"+
			"HeaderOptRwOffset = %016X\n"+
			"isPointerAligned  = %t\n",
		o.Version,
		o.Flags,
		o.SelectorOptOffset,
		o.HeaderOptRoOffset,
		o.ClassOptOffset,
		o.ProtocolOptOffset,
		o.HeaderOptRwOffset,
		o.isPointerAligned())
}

// Precomputed perfect hash table of strings.
// Base class for precomputed selector table and class table.
type stringHash struct {
	Capacity uint32
	Occupied uint32
	Shift    uint32
	Mask     uint32
	_        uint32 // was zero
	_        uint32 // alignment pad
	Salt     uint64
	Scramble [256]uint32
}

// StringHash struct
type StringHash struct {
	FileOffset int64
	stringHash
	Tab        []byte  /* tab[mask+1] (always power-of-2) */
	CheckBytes []byte  /* check byte for each string */
	Offsets    []int32 /* offsets from &capacity to cstrings */
}

func (s StringHash) String() string {
	return fmt.Sprintf(
		"FileOffset = %X\n"+
			"Capacity   = %X\n"+
			"Occupied   = %X\n"+
			"Shift      = %X\n"+
			"Mask       = %X\n"+
			"Salt       = %016X\n",
		s.FileOffset,
		s.Capacity,
		s.Occupied,
		s.Shift,
		s.Mask,
		s.Salt)
}

func (f *File) getLibObjC() (*macho.File, error) {
	image := f.Image("/usr/lib/libobjc.A.dylib")

	m, err := image.GetMacho()
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (f *File) dumpOffsets(offsets []int32, fileOffset int64) {
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)
	for _, ptr := range offsets {
		if ptr != 0 {
			sr.Seek(int64(int32(fileOffset)+ptr), io.SeekStart)
			s, err := bufio.NewReader(sr).ReadString('\x00')
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to read selector name at: %d", int32(fileOffset)+ptr).Error())
			}
			addr, _ := f.getVMAddress(uint64(int32(fileOffset) + ptr))
			fmt.Printf("    0x%x: %s\n", addr, strings.Trim(s, "\x00"))
		}

	}
}

func (f *File) offsetsToMap(offsets []int32, fileOffset int64) map[string]uint64 {
	objcMap := make(map[string]uint64)

	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)
	for _, ptr := range offsets {
		if ptr != 0 {
			sr.Seek(int64(int32(fileOffset)+ptr), io.SeekStart)
			s, err := bufio.NewReader(sr).ReadString('\x00')
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to read selector name at: %d", int32(fileOffset)+ptr).Error())
			}
			addr, _ := f.getVMAddress(uint64(int32(fileOffset) + ptr))
			objcMap[strings.Trim(s, "\x00")] = addr
		}

	}
	return objcMap
}

// GetSelectorAddress returns a selector name's address
func (f *File) GetSelectorAddress(selector string) (uint64, error) {

	image := f.Image("/usr/lib/libobjc.A.dylib")

	dat, err := image.Data()
	if err != nil {
		return 0, err
	}
	r := bytes.NewReader(dat)

	m, err := macho.NewFile(r)
	if err != nil {
		return 0, err
	}

	for _, s := range m.Sections {
		if s.Seg == "__TEXT" && s.Name == "__objc_opt_ro" {

			opt := Optimization{}
			if err := binary.Read(s.Open(), f.ByteOrder, &opt); err != nil {
				return 0, err
			}
			if opt.Version != 15 {
				return 0, fmt.Errorf("objc optimization version should be 15, but found %d", opt.Version)
			}

			log.Debugf("Objective-C Optimization:\n%s", opt)

			shash := StringHash{FileOffset: int64(s.Offset) + int64(opt.SelectorOptOffset)}
			// shash := StringHash{FileOffset: int32(s.Offset) + opt.HeaderOptRoOffset}
			// shash := StringHash{FileOffset: int32(s.Offset) + opt.ClassOptOffset}
			// shash := StringHash{FileOffset: int32(s.Offset) + opt.ProtocolOptOffset}
			// shash := StringHash{FileOffset: int32(s.Offset) + opt.HeaderOptRwOffset}

			r.Seek(int64(shash.FileOffset), io.SeekStart)
			if err := binary.Read(r, f.ByteOrder, &shash.stringHash); err != nil {
				return 0, err
			}

			log.Debugf("Objective-C StringHash:\n%s", shash)

			shash.Tab = make([]byte, shash.Mask+1)
			if err := binary.Read(r, f.ByteOrder, &shash.Tab); err != nil {
				return 0, err
			}

			shash.CheckBytes = make([]byte, shash.Capacity)
			if err := binary.Read(r, f.ByteOrder, &shash.CheckBytes); err != nil {
				return 0, err
			}

			shash.Offsets = make([]int32, shash.Capacity)
			if err := binary.Read(r, f.ByteOrder, &shash.Offsets); err != nil {
				return 0, err
			}

			selIndex, err := shash.getIndex(selector)
			if err != nil {
				return 0, errors.Wrapf(err, "failed get selector address for %s", selector)
			}

			ptr, _ := f.getVMAddress(uint64(shash.FileOffset + int64(shash.Offsets[selIndex])))

			return ptr, nil
		}
	}

	return 0, fmt.Errorf("failed get selector address for %s", selector)
}

// SelectorsForImage returns all of the Objective-C selectors for a given image
func (f *File) SelectorsForImage(imageNames ...string) error {
	var mask uint64 = (1 << 40) - 1 // 40bit mask
	var images []*CacheImage

	libobjc, err := f.getLibObjC()
	if err != nil {
		return err
	}

	if len(imageNames) > 0 && len(imageNames[0]) > 0 {
		for _, imageName := range imageNames {
			images = append(images, f.Image(imageName))
		}
	} else {
		images = f.Images
	}
	fmt.Println("Objective-C Selectors:")
	for _, image := range images {
		fmt.Println(image.Name)
		m, err := image.GetMacho()
		if err != nil {
			return errors.Wrapf(err, "failed get image %s as MachO", image.Name)
		}
		for _, s := range m.Sections {
			if s.Seg == "__DATA" && s.Name == "__objc_selrefs" {
				selectorPtrs := make([]uint64, s.Size/8)
				if err := binary.Read(s.Open(), f.ByteOrder, &selectorPtrs); err != nil {
					return err
				}
				for idx, ptr := range selectorPtrs {
					selectorPtrs[idx] = ptr & mask
				}

				objcRoSeg := libobjc.Segment("__OBJC_RO")
				if objcRoSeg == nil {
					fmt.Println("  - No selectors.")
					return fmt.Errorf("segment __OBJC_RO does not exist")
				}

				sr := objcRoSeg.Open()
				for _, ptr := range selectorPtrs {
					sr.Seek(int64(ptr-objcRoSeg.Addr), io.SeekStart)
					s, err := bufio.NewReader(sr).ReadString('\x00')
					if err != nil {
						log.Error(errors.Wrapf(err, "failed to read selector name at: %d", ptr-objcRoSeg.Addr).Error())
					}
					fmt.Printf("    0x%x: %s\n", ptr, strings.Trim(s, "\x00"))
				}
			}
		}
		m.Close()
	}
	return nil
}

func isASCII(s string) bool {
	if len(s) < 1 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// AllSelectors is a dumb brute force way to get all the ObjC selector/class etc address
// by just dumping all the strings in the __OBJC_RO segment
// returns: map[sym]addr
func (f *File) AllSelectors(print bool) (map[string]uint64, error) {

	image := f.Image("/usr/lib/libobjc.A.dylib")

	dat, err := image.Data()
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(dat)

	m, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}

	for _, s := range m.Sections {
		if s.Seg == "__TEXT" && s.Name == "__objc_opt_ro" {

			opt := Optimization{}
			if err := binary.Read(s.Open(), f.ByteOrder, &opt); err != nil {
				return nil, err
			}
			if opt.Version != 15 {
				return nil, fmt.Errorf("objc optimization version should be 15, but found %d", opt.Version)
			}

			log.Debugf("Objective-C Optimization:\n%s", opt)

			shash := StringHash{FileOffset: int64(s.Offset) + int64(opt.SelectorOptOffset)}
			// shash := StringHash{FileOffset: int32(s.Offset) + opt.HeaderOptRoOffset}
			// shash := StringHash{FileOffset: int32(s.Offset) + opt.ClassOptOffset}
			// shash := StringHash{FileOffset: int32(s.Offset) + opt.ProtocolOptOffset}
			// shash := StringHash{FileOffset: int32(s.Offset) + opt.HeaderOptRwOffset}

			r.Seek(int64(shash.FileOffset), io.SeekStart)
			if err := binary.Read(r, f.ByteOrder, &shash.stringHash); err != nil {
				return nil, err
			}

			log.Debugf("Objective-C StringHash:\n%s", shash)

			shash.Tab = make([]byte, shash.Mask+1)
			if err := binary.Read(r, f.ByteOrder, &shash.Tab); err != nil {
				return nil, err
			}

			shash.CheckBytes = make([]byte, shash.Capacity)
			if err := binary.Read(r, f.ByteOrder, &shash.CheckBytes); err != nil {
				return nil, err
			}

			shash.Offsets = make([]int32, shash.Capacity)
			if err := binary.Read(r, f.ByteOrder, &shash.Offsets); err != nil {
				return nil, err
			}

			if print {
				f.dumpOffsets(shash.Offsets, shash.FileOffset)
			}
			return f.offsetsToMap(shash.Offsets, shash.FileOffset), nil
		}
	}

	return nil, fmt.Errorf("unable to find __TEXT.__objc_opt_ro")
}

/*
--------------------------------------------------------------------
mix -- mix 3 64-bit values reversibly.
mix() takes 48 machine instructions, but only 24 cycles on a superscalar
  machine (like Intel's new MMX architecture).  It requires 4 64-bit
  registers for 4::2 parallelism.
All 1-bit deltas, all 2-bit deltas, all deltas composed of top bits of
  (a,b,c), and all deltas of bottom bits were tested.  All deltas were
  tested both on random keys and on keys that were nearly all zero.
  These deltas all cause every bit of c to change between 1/3 and 2/3
  of the time (well, only 113/400 to 287/400 of the time for some
  2-bit delta).  These deltas all cause at least 80 bits to change
  among (a,b,c) when the mix is run either forward or backward (yes it
  is reversible).
This implies that a hash using mix64 has no funnels.  There may be
  characteristics with 3-bit deltas or bigger, I didn't test for
  those.
--------------------------------------------------------------------
*/
func mix64(a, b, c *uint64) {
	*a = (*a - *b - *c) ^ (*c >> 43)
	*b = (*b - *c - *a) ^ (*a << 9)
	*c = (*c - *a - *b) ^ (*b >> 8)
	*a = (*a - *b - *c) ^ (*c >> 38)
	*b = (*b - *c - *a) ^ (*a << 23)
	*c = (*c - *a - *b) ^ (*b >> 5)
	*a = (*a - *b - *c) ^ (*c >> 35)
	*b = (*b - *c - *a) ^ (*a << 49)
	*c = (*c - *a - *b) ^ (*b >> 11)
	*a = (*a - *b - *c) ^ (*c >> 12)
	*b = (*b - *c - *a) ^ (*a << 18)
	*c = (*c - *a - *b) ^ (*b >> 22)
}

/*
--------------------------------------------------------------------
hash() -- hash a variable-length key into a 64-bit value
  k     : the key (the unaligned variable-length array of bytes)
  len   : the length of the key, counting by bytes
  level : can be any 8-byte value
Returns a 64-bit value.  Every bit of the key affects every bit of
the return value.  No funnels.  Every 1-bit and 2-bit delta achieves
avalanche.  About 41+5len instructions.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 64 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (uint8_t **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = hash( k[i], len[i], h);

By Bob Jenkins, Jan 4 1997.  bob_jenkins@burtleburtle.net.  You may
use this code any way you wish, private, educational, or commercial,
but I would appreciate if you give me credit.

See http://burtleburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^^64
is acceptable.  Do NOT use for cryptographic purposes.
--------------------------------------------------------------------
*/

func lookup8(k []byte, level uint64) uint64 {
	// uint8_t *k;        /* the key */
	// uint64_t  length;   /* the length of the key */
	// uint64_t  level;    /* the previous hash, or an arbitrary value */
	var a, b, c uint64
	var length int

	/* Set up the internal state */
	length = len(k)
	a = level
	b = level              /* the previous hash value */
	c = 0x9e3779b97f4a7c13 /* the golden ratio; an arbitrary value */
	p := 0
	/*---------------------------------------- handle most of the key */
	for length >= 24 {
		a += uint64(k[p+0]) + (uint64(k[p+1]) << 8) + (uint64(k[p+2]) << 16) + (uint64(k[p+3]) << 24) + (uint64(k[p+4]) << 32) + (uint64(k[p+5]) << 40) + (uint64(k[p+6]) << 48) + (uint64(k[p+7]) << 56)
		b += uint64(k[p+8]) + (uint64(k[p+9]) << 8) + (uint64(k[p+10]) << 16) + (uint64(k[p+11]) << 24) + (uint64(k[p+12]) << 32) + (uint64(k[p+13]) << 40) + (uint64(k[p+14]) << 48) + (uint64(k[p+15]) << 56)
		c += uint64(k[p+16]) + (uint64(k[p+17]) << 8) + (uint64(k[p+18]) << 16) + (uint64(k[p+19]) << 24) + (uint64(k[p+20]) << 32) + (uint64(k[p+21]) << 40) + (uint64(k[p+22]) << 48) + (uint64(k[p+23]) << 56)
		mix64(&a, &b, &c)
		p += 24
		length -= 24
	}

	/*------------------------------------- handle the last 23 bytes */
	c += uint64(len(k))
	switch length { /* all the case statements fall through */
	case 23:
		c += (uint64(k[p+22]) << 56)
		fallthrough
	case 22:
		c += (uint64(k[p+21]) << 48)
		fallthrough
	case 21:
		c += (uint64(k[p+20]) << 40)
		fallthrough
	case 20:
		c += (uint64(k[p+19]) << 32)
		fallthrough
	case 19:
		c += (uint64(k[p+18]) << 24)
		fallthrough
	case 18:
		c += (uint64(k[p+17]) << 16)
		fallthrough
	case 17:
		c += (uint64(k[p+16]) << 8)
		fallthrough
	/* the first byte of c is reserved for the length */
	case 16:
		b += (uint64(k[p+15]) << 56)
		fallthrough
	case 15:
		b += (uint64(k[p+14]) << 48)
		fallthrough
	case 14:
		b += (uint64(k[p+13]) << 40)
		fallthrough
	case 13:
		b += (uint64(k[p+12]) << 32)
		fallthrough
	case 12:
		b += (uint64(k[p+11]) << 24)
		fallthrough
	case 11:
		b += (uint64(k[p+10]) << 16)
		fallthrough
	case 10:
		b += (uint64(k[p+9]) << 8)
		fallthrough
	case 9:
		b += (uint64(k[p+8]))
		fallthrough
	case 8:
		a += (uint64(k[p+7]) << 56)
		fallthrough
	case 7:
		a += (uint64(k[p+6]) << 48)
		fallthrough
	case 6:
		a += (uint64(k[p+5]) << 40)
		fallthrough
	case 5:
		a += (uint64(k[p+4]) << 32)
		fallthrough
	case 4:
		a += (uint64(k[p+3]) << 24)
		fallthrough
	case 3:
		a += (uint64(k[p+2]) << 16)
		fallthrough
	case 2:
		a += (uint64(k[p+1]) << 8)
		fallthrough
	case 1:
		a += uint64(k[p+0])
		/* case 0: nothing left to add */
	}
	mix64(&a, &b, &c)
	/*-------------------------------------------- report the result */
	return c
}

func (s StringHash) hash(key []byte) uint32 {
	val := lookup8(key, s.Salt)
	index := (val >> uint64(s.Shift)) ^ uint64(s.Scramble[s.Tab[(val&uint64(s.Mask))]])
	return uint32(index)
}

// The check bytes are used to reject strings that aren't in the table
// without paging in the table's cstring data. This checkbyte calculation
// catches 4785/4815 rejects when launching Safari; a perfect checkbyte
// would catch 4796/4815.
func checkbyte(key []byte) uint8 {
	return ((key[0] & 0x7) << 5) | (uint8(len(key)) & 0x1f)
}

func (s StringHash) getIndex(keyStr string) (uint32, error) {
	key := []byte(keyStr)

	h := s.hash(key)

	// Use check byte to reject without paging in the table's cstrings
	hCheck := s.CheckBytes[h]
	keyCheck := checkbyte(key)
	if hCheck != keyCheck {
		return 0, fmt.Errorf("INDEX_NOT_FOUND")
	}

	offset := s.Offsets[h]
	if offset == 0 {
		return 0, fmt.Errorf("INDEX_NOT_FOUND")
	}
	// result = (const char *)this + offset
	// TODO: fix me
	// result := "FIX ME"
	// if result != string(key) {
	// 	return 0, fmt.Errorf("INDEX_NOT_FOUND")
	// }

	return h, nil
}
