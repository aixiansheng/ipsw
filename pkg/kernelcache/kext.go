package kernelcache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strconv"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	. "golang.org/x/arch/arm64/arm64asm"
)

// Convert this to go-macho after the next version is incorporated into ipsw.
type Segment64 struct {
	LoadCmd   uint32
	Len       uint32
	Name      [16]byte
	Addr      uint64
	Memsz     uint64
	Offset    uint64
	Filesz    uint64
	Maxprot   uint32
	Prot      uint32
	Nsect     uint32
	Flag      uint32
}

type Section64 struct {
	Name      [16]byte
	Seg       [16]byte
	Addr      uint64
	Size      uint64
	Offset    uint32
	Align     uint32
	Reloff    uint32
	Nreloc    uint32
	Flags     uint32
	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32
}

var UUID64Len uint32 = 0x18
var UUID64Cmd uint32 = 0x1b

type UUID64 struct {
	LoadCmd uint32
	Len	uint32
	Bytes	[16]byte
}

// KextList lists all the kernel extensions in the kernelcache
func KextList(kernel string) error {
	kc, err := NewKernelCache(kernel)
	if err != nil {
		return err
	}
	defer kc.Close()

	prelink, err := kc.PrelinkInfoDict()
	if err != nil {
		return err
	}

	fmt.Println("FOUND:", len(prelink.PrelinkInfoDictionary))
	prelink.ForeachBundle(func(bundle * CFBundle) error {
		fmt.Printf("%s (%s)\n", bundle.ID, bundle.Version)
		return nil
	})

	return nil
}

// unSeek performs thingy() and seeks fh back to its position before thingy() was performed.
func unSeek(fh * os.File, thingy func() error) error {
	var startSeek int64
	var err error
	if startSeek, err = fh.Seek(0, io.SeekCurrent); err != nil {
		return err
	}

	err = thingy()

	if _, seekBackErr := fh.Seek(startSeek, io.SeekStart); seekBackErr != nil {
		return seekBackErr
	}

	return err
}

type Kext interface {
	io.WriterTo
	io.Reader
	KernelCache() * KernelCache
	KextMachO() * macho.File
	Name() string
}

type KextBase struct {
	Kc * KernelCache
	MachO * macho.File
	KextName string
}

func NewKextBase(kc * KernelCache, m * macho.File, name string) * KextBase {
	return &KextBase{
		Kc: kc,
		MachO: m,
		KextName: name,
	}
}

func (kb * KextBase) Read(b []byte) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (kb * KextBase) KernelCache() * KernelCache {
	return kb.Kc
}

func (kb * KextBase) KextMachO() * macho.File {
	return kb.MachO
}

func (kb * KextBase) Name() string {
	return kb.KextName
}

type SplitKext struct {
	KextBase
	splitKext []byte
}

func NewSplitKext(kc * KernelCache, m * macho.File, name string) * SplitKext {
	return &SplitKext{
		KextBase: KextBase{
			Kc: kc,
			MachO: m,
			KextName: name,
		},
	}
}

func (sk * SplitKext) WriteTo(w io.Writer) (n int64, err error) {
	r := bytes.NewReader(sk.splitKext)
	return io.Copy(w, r)
}

type CoalescedKext struct {
	KextBase
	coalescedSections []coalescedSectionWithMetrics
	coalescedMachO * modifiedMachO
}

func NewCoalescedKext(kc * KernelCache, m * macho.File, name string) * CoalescedKext {
	return &CoalescedKext{
		KextBase: KextBase{
			Kc: kc,
			MachO: m,
			KextName: name,
		},
		coalescedSections: make([]coalescedSectionWithMetrics, 0, 6),
	}
}

func (ck * CoalescedKext) AddCoalescedSection(address uint64, size uint64, name, seg string, met * coalesceMetrics) {
	cs := coalescedSectionWithMetrics{
		Section: name,
		Segment: seg,
		Address: address,
		Size: uint64(size),
		Metrics: met,
	}
	ck.coalescedSections = append(ck.coalescedSections, cs)
}

func (ck * CoalescedKext) WriteTo(w io.Writer) (int64, error) {
	n, err := ck.coalescedMachO.write(w)
	return int64(n), err
}

func roundUp64(x, y uint64) uint64 {
	return (x + y) & (^(y - 1))
}

func pageAddr(x uint64) uint64 {
	return x & 0xffff_ffff_ffff_f000
}

func (kc * KernelCache) ExtractKext(kextName string, kext * macho.File) (Kext, error) {
	log.Warnf("Extracting kext: %s", kextName)

	switch kc.Format {
	case SplitCache:
		return extractKextFromSplitCache(kextName, kc, kext)
	case CoalescedDataCache:
		return extractKextFromCoalescedCache(kextName, kc, kext)
	default:
		return nil, fmt.Errorf("Unsupported kernel cache format")
	}
}

// ExtractKext locates the specified kext and writes it to a file with the same name.
func (kc * KernelCache) ExtractKextWithName(kextName string) (Kext, error) {
	kext, err := kc.KextWithName(kextName)
	if err != nil {
		return nil, err
	}

	return kc.ExtractKext(kextName, kext)
}

func extractKextFromCoalescedCache(kextName string, kc * KernelCache, kext * macho.File) (*CoalescedKext, error) {
	/*
	 * How to write a kext (method used for coalesced kernel segments)
	 *   - identify coalesced kernel sections
	 *   - find and save its text segment, sections, and data
	 *   - create its data segments and sections by searching for ADRP references that refer to coalesced segments/sections
	 *   - modify the text segment by adding the data segment/sections (try adding it after the other load commands)
	 *   - write the new macho (text, data segments)
	 */

	ck := NewCoalescedKext(kc, kext, kextName)

	plkOffsets, err := kc.PrelinkOffsets()
	if err != nil {
		return nil, err
	}

	kernelSegments, err := kc.MainKernelSegments()
	if err != nil {
		return nil, err
	}

	textBase := kc.GetTextBase()
	if textBase == 0 {
		return nil, fmt.Errorf("Couldn't get text base")
	}

	ck.coalescedMachO = newModifiedMachO(kext, textBase, plkOffsets, true)
	modMachO := &ck.coalescedMachO

	// Get the referenced regions from the kext's __TEXT_EXEC segment
	textSeg := kext.SegmentByName("__TEXT_EXEC")
	if textSeg == nil {
		return nil, fmt.Errorf("Couldn't find the kext's text segment")
	}

	textSegData, err := textSeg.Data()
	if err != nil {
		return nil, err
	}

	refs := regionsReferencedInRegion(textSegData, textSeg.Addr);

	for _, segment := range kernelSegments {
		if segment.Name == "__LINKEDIT" {
			continue
		}

		fixUpSegment(segment, textBase, plkOffsets, true)
		segWithSecs := newSegmentWithSections(segment)

		hasCoalescedSections := false
		numSectionsCoalesced := 0
		ForeachSectionInSegment(kc.GetKernelMachO(), segment, func(section * macho.Section) {
			fixUpSection(section, textBase, plkOffsets, true)
			if coalesced, met := coalesceRegionsWithinAddressRange(refs, section.Addr, section.Size); coalesced != nil {
				hasCoalescedSections = true
				numSectionsCoalesced += 1

				log.Infof("Coalesced within section %8s %8s: [ 0x%.16x - 0x%.16x ] (%x bytes)",
					section.Seg,
					section.Name,
					section.Addr,
					section.Addr + section.Size,
					section.Size,
				)

				log.Infof("  [ 0x%.16x - 0x%.16x (0x%x) ]",
					coalesced.start,
					coalesced.start + coalesced.size,
					coalesced.size,
				)

				met.print()

				/*
				 * Adjust the section's address and size to only contain the coalesced region.  Round to 0x1000
				 * on start/end.
				 */
				ck.AddCoalescedSection(coalesced.start, coalesced.size, section.Name, section.Seg, met)
				sectWithData := sliceSection(section, coalesced)
				segWithSecs.addSectionWithData(sectWithData)
			}
		})

		if hasCoalescedSections {
			segment.Nsect = uint32(numSectionsCoalesced)
			(*modMachO).addSegmentWithSections(segWithSecs)
		}
	}

	return ck, nil
}

func extractKextFromSplitCache(kextName string, kc * KernelCache, kext * macho.File) (*SplitKext, error) {
	/*
	 * How to write a kext in 2 easy steps: (old way)
	 *   One: Iterate over the segs, write them out (text includes MH and segs!)
	 *   Two: Go back and fix the segments and sections (Slide the offsets so
	 *        that the next tool to read them will work)
	 */

	sk := NewSplitKext(kc, kext, kextName)

	plkOffsets, err := kc.PrelinkOffsets()
	if err != nil {
		return nil, err
	}

	textBase := kc.GetTextBase()
	if textBase == 0 {
		return nil, fmt.Errorf("Couldn't get text base")
	}

	log.Debug("Copying Segment data...")

	fh, err := ioutil.TempFile("", "kext")
	if err != nil {
		return nil, err
	}

	defer os.Remove(fh.Name())

	var segOffset uint64
	segOffsets := make([]uint64, 0)
	for _, seg := range kext.Segments() {
		slidOffset := plkOffsets.SlideOffset(seg.Name, fixUpPointer(textBase, seg.Addr))
		log.Infof("%16s: Address: 0x%.16x Offset [0x%.16x -> 0x%.16x (0x%.16x)] %d bytes",
			seg.Name, fixUpPointer(textBase, seg.Addr), seg.Offset,
			seg.Offset, slidOffset, seg.Filesz)

		// Split cached kernel layout.  Offset is slid based on prelink segment/offset delta.
		seg.Offset = slidOffset

		// round the segment's on-disk size up to 4096
		segDiskSize := roundUp64(seg.Filesz, 0x1000)
		segDatum := make([]byte, segDiskSize)
		if seg.Name != "__LINKEDIT" {
			if n, err := kc.Reader().ReadAt(segDatum[:seg.Filesz], int64(seg.Offset)); n != int(seg.Filesz) {
				log.Errorf("  Couldn't read segment data at %x: %v", seg.Offset, err)
			}
		}

		if n, err := fh.Write(segDatum); n != len(segDatum) {
			log.Errorf("Couldn't write segment data: %v", err)
			return nil, err
		}

		segOffsets = append(segOffsets, uint64(segOffset))
		segOffset += segDiskSize
	}

	log.Debugf("Fixing segment and section offsets for %d segments...", len(segOffsets))

	// Seek past the mach-o header in the output file.
	var mhSize int64 = 8 * 4
	if _, err := fh.Seek(mhSize, io.SeekStart); err != nil {
		return nil, err
	}

	/*
	 * Note:  Addresses aren't fixed up in the kext that's been written.  It's probably better
	 * to leave it that way for post-processing that knows the original text base.
	 */
	for i := 0; i < len(segOffsets); i++ {
		var segHeader Segment64
		err := unSeek(fh, func() error {
			if err2 := binary.Read(fh, binary.LittleEndian, &segHeader); err2 != nil {
				log.Errorf("Couldn't read segment header: %v", err2)
				return err2
			}
			return nil
		})

		if err != nil {
			log.Errorf("Failed to read segment header: %v", err)
			return nil, err
		}

		// Calculate the difference in the segment's file offset so that it can be applied to each section.
		origOffset := segHeader.Offset
		segHeader.Offset = segOffsets[i]
		offsetDelta := segHeader.Offset - origOffset

		if err = binary.Write(fh, binary.LittleEndian, &segHeader); err != nil {
			log.Errorf("Failed to write segment header: %v", err)
			return nil, err
		}

		log.Debugf("Fixing up sections [%d]", segHeader.Nsect)

		for i := 0; i < int(segHeader.Nsect); i++ {
			var sectHeader Section64

			err = unSeek(fh, func() error {
				if err2 := binary.Read(fh, binary.LittleEndian, &sectHeader); err2 != nil {
					log.Errorf("Couldn't read section header: %v", err2)
					return err2
				}
				return nil
			})

			if err != nil {
				log.Errorf("Failed to read section header: %v", err)
				return nil, err
			}

			// DATA/bss has an offset of 0, it's not mapped from the file, so don't add an offset to it.
			usedDelta := offsetDelta
			if sectHeader.Offset == 0 {
				usedDelta = 0
			}

			log.Infof("%16s, %16s:  Offset 0x%.16x + 0x%.16x -> ",
				string(bytes.Trim(segHeader.Name[:], "\x00")),
				string(bytes.Trim(sectHeader.Name[:], "\x00")),
				sectHeader.Offset,
				usedDelta)

			sectHeader.Offset += uint32(usedDelta)

			if err = binary.Write(fh, binary.LittleEndian, &sectHeader); err != nil {
				log.Errorf("Failed to write section header: %v", err)
				return nil, err
			}
		}
	}

	if _, err = fh.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	b := new(bytes.Buffer)

	_, err = io.Copy(b, fh)
	if err != nil {
		return nil, err
	}

	sk.splitKext = b.Bytes()

	return sk, nil
}

type region struct {
	start uint64
	size uint64
}

func regionsReferencedInRegion(payload []byte, address uint64) []region {
	refs := make([]region, 0, 1024)

	for i := 0; i < len(payload) - 4; i += 4 {
		b := payload[i:i+4]

		var err error
		var inst Inst
		if inst, err = Decode(b); err != nil {
			continue
		}

		if inst.Op != ADRP {
			continue
		}

		pageOffsetStr := inst.Args[1].String()[2:]
		if pageOffset, err := strconv.ParseUint(pageOffsetStr, 0, 64); err != nil {
			return nil
		} else {
			var instAddr uint64 = address + uint64(i)

			// Don't know the size of the ref, assume 8.
			refSize := estimateRefSize(payload, i, inst.Args[0].String())
			addrRange := region{ instAddr + pageOffset, refSize }
			refs = append(refs, addrRange)
		}
	}

	sort.Slice(refs, func(i, j int) bool {
		return refs[i].start < refs[j].start
	})

	return refs
}

func estimateRefSize(region []byte, offset int, register string) uint64 {
	// It may be possible to scan forward and find uses of the assigned register
	// until a function return/branch instruction... (nothing complicated)
	// But for now, just return 8
	return 8
}

func roundUpRangeSize(r * region, size uint64) {
	if r.size < size {
		r.size = size
	}
}

func regionEnd(r * region) uint64 {
	return r.start + uint64(r.size)
}

type coalesceMetrics struct {
	address uint64
	size	uint64
	max 	uint64
	total	uint64
	num	uint64
	avg	uint64
	percentOfRangeOccupied float64
}

func newCoalesceMetrics(address, size uint64) *coalesceMetrics {
	return &coalesceMetrics{
		address: address,
		size: size,
	}
}

func (m * coalesceMetrics) addDistance(d uint64) {
	if d > m.max {
		m.max = d
	}

	m.total += d
	m.num ++

	m.avg = m.total / m.num
	m.percentOfRangeOccupied = float64(m.total) / float64(m.size)
}

func (m * coalesceMetrics) print() {
	log.Infof("  Total regions coalesced: %d (%%%.1f)", m.total, m.percentOfRangeOccupied * 100)
	log.Infof("    [ avg: %d / 0x%x ]", m.avg, m.avg)
	log.Infof("    [ max: %d / 0x%x ]", m.max, m.max)
}

func coalesceRegionsWithinAddressRange(regions []region, address, size uint64) (*region, *coalesceMetrics) {
	metrics := newCoalesceMetrics(address, size)

	var coalesced region
	for i := 0; i < len(regions); i++ {
		cur := &regions[i]
		if cur.start >= address {
			if regionEnd(cur) < address + size {
				if coalesced.start == 0 && coalesced.size == 0 {
					coalesced = *cur
				} else {
					if cur.start > regionEnd(&coalesced) {
						distance := cur.start - regionEnd(&coalesced) 
						metrics.addDistance(distance)
					}

					if regionEnd(cur) > regionEnd(&coalesced) {
						coalesced.size += regionEnd(cur) - regionEnd(&coalesced)
					}
				}
			} else {
				break
			}
		}
	}

	if coalesced.start != 0 || coalesced.size != 0 {
		return &coalesced, metrics
	} else {
		return nil, nil
	}
}

func fixUpSection(sec * macho.Section, textBase uint64, plkOffsets * prelinkOffsets, isKernelMachO bool) {
	var secOffset uint64 = uint64(sec.Offset)
	fixUpAddrOffset(&sec.Addr, &secOffset, sec.Seg, textBase, plkOffsets, isKernelMachO)
	sec.Offset = uint32(secOffset)
}

func fixUpSegment(seg * macho.Segment, textBase uint64, plkOffsets * prelinkOffsets, isKernelMachO bool) {
	fixUpAddrOffset(&seg.Addr, &seg.Offset, seg.Name, textBase, plkOffsets, isKernelMachO)
}

func fixUpAddrOffset(addr, offset * uint64, segName string, textBase uint64, plkOffsets * prelinkOffsets, isKernelMachO bool) {
	if !isKernelMachO {
		if *offset == 0 {
			// New cached kernel layout.  Kext headers have 0 offsets.  Offset = Addr - Kernel Base Address.
			*addr = fixUpPointer(textBase, *addr)
			*offset = *addr - textBase
		} else {
			// Split cached kernel layout.  Offset is slid based on prelink segment/offset delta.
			*offset = plkOffsets.SlideOffset(segName, fixUpPointer(textBase, *addr))
		}
	} else {
		*addr = fixUpPointer(textBase, *addr)
		*offset = *addr - textBase
	}
}

type sectionWithData struct {
	section * Section64
	data []byte
}

type segmentWithData struct {
	segment * macho.Segment
	data []byte
}

type segmentWithSections struct {
	segment * segmentWithData
	sections []sectionWithData
}

func sliceSection(section * macho.Section, region * region) * sectionWithData {
	data, err := section.Data()
	if err != nil {
		return nil
	}

	endAddr := region.start + region.size
	//newAddr := pageAddr(region.start)
	newAddr := region.start

	// Not sure if alignment is necessary, the linker may have ignored it when it coalesced the kext segments.
	//endAddr = roundUp64(endAddr, uint64(math.Pow(2, float64(section.Align))))
	newSize := endAddr - newAddr

	startOffset := newAddr - section.Addr
	endOffset := startOffset + newSize
	sectionData := data[startOffset:endOffset]

	s64 := bugfixSectionToSection64(section)
	s64.Addr = newAddr
	s64.Size = newSize

	return &sectionWithData{
		section: s64,
		data: sectionData,
	}
}

type modifiedMachO struct {
	header types.FileHeader
	segments []segmentWithSections
	headerSize int
	origHeaderSize int
	// extraLoadCommands...
}

func newModifiedMachO(old * macho.File, textBase uint64, plkOffsets * prelinkOffsets, isKernelMachO bool) * modifiedMachO {
	m := &modifiedMachO{
		header: old.FileHeader,
		segments: make([]segmentWithSections, 0, 6),
	}

	m.header.NCommands = 0
	m.header.SizeCommands = 0
	m.headerSize = 32

	for _, seg := range old.Segments() {
		fixUpSegment(seg, textBase, plkOffsets, isKernelMachO)
		sws := newSegmentWithSections(seg)
		ForeachSectionInSegment(old, seg, func(section * macho.Section) {
			fixUpSection(section, textBase, plkOffsets, isKernelMachO)
			sectData, _ := section.Data()
			s64 := bugfixSectionToSection64(section)
			swd := sectionWithData{
				section: s64,
				data: sectData,
			}
			sws.addSectionWithData(&swd)
		})
		m.segments = append(m.segments, *sws)
		m.header.NCommands += 1
		m.header.SizeCommands += seg.Len
	}

	m.origHeaderSize = int(old.SizeCommands) + m.headerSize

	return m
}

func (m * modifiedMachO) addSegmentWithSections(sws * segmentWithSections) {
	m.segments = append(m.segments, *sws)
	m.header.NCommands += 1
	m.header.SizeCommands += sws.segment.segment.Len
}

func (m * modifiedMachO) write(origWriter io.Writer) (int, error) {
	var total writeCounter
	dbg := new (bytes.Buffer)
	w := io.MultiWriter(origWriter, &total, dbg)
	buf := make([]byte, 256)

	/*
	 * When writing the modified Mach-O, there's likely no space for more
	 * load commands before the __TEXT_EXEC/__text section starts in vm-space.
	 * Move the first (__TEXT_EXEC) segment's vm address up a bit so that we have
	 * space.  (Otherwise, we'd have to slide it relative to its data segment.)
	 * 
	 * Also, write the original mh where it's expected to be (sometimes there
	 * are references to it.)
	 */

	used := m.header.Put(buf, binary.LittleEndian)
	if _, err := w.Write(buf[:used]); err != nil {
		return int(total), err
	}

	/*
	 * The layout should be: MH | Seg, (sects) | Seg, (sects)... |
	 * The Offset of the first segment (which was likely the TEXT_EXEC
	 * segment from the original mach-o should be the offset to the actual
	 * data.. We can determine this by calculating the combined .Len of 
	 * each segment in the macho.  Each other seg/sect offset will not
	 * increment by the total bytes written, but by the len() of the data
	 * before it... (so if a segment has data...)
	 *
	 * Should we coalesce sections into segment data and only write segs?
	 */

	segmentDataOffset := m.headerSize + int(m.header.SizeCommands)
	totalHeadersSize := uint64(m.headerSize + int(m.header.SizeCommands))
	totalHeaderVmSize := roundUp64(totalHeadersSize, 0x1000)
	totalHeaderVmSize += 0x1000

	textSeg := m.segments[0]
	textSeg.segment.segment.Addr -= totalHeaderVmSize

	textSegAddrPageAddr := pageAddr(textSeg.segment.segment.Addr)
	textSeg.segment.segment.Memsz += totalHeaderVmSize + textSeg.segment.segment.Addr - textSegAddrPageAddr
	textSeg.segment.segment.Addr = textSegAddrPageAddr

	/*
	 * First, write the load commands, tracking the number of bytes written
	 * and writing the segment and section offsets
	 */
	for segno, sws := range m.segments {
		seg := sws.segment
		seg.segment.Offset = uint64(segmentDataOffset)

		if err := writeSegment(w, seg.segment); err != nil {
			return int(total), err
		}

		for sectno, swd := range sws.sections {
			sect := swd.section

			if segno == 0 && sectno == 0 {
				/* 
				 * The first segment has header data that should be included in the output.
				 * But all other segments will just contain section data
				 */
				segmentDataOffset += m.origHeaderSize
			}

			sect.Offset = uint32(segmentDataOffset)

			if err := writeSection(w, sect); err != nil {
				return int(total), err
			}

			segmentDataOffset += len(swd.data)
		}
	}

	/*
	 * Now, write the section data.  The assumption is that section data
	 * includes all useful segment data, except for segment 1, where the
	 * original MH resides, and must be written separately.
	 */

	for segno, sws := range m.segments {
		seg := sws.segment
		if segno == 0 {
			// The first segment contains the old MH before the first section.  Write it.
			if _, err := w.Write(seg.data[:m.origHeaderSize]); err != nil {
				return int(total), err
			}
		}

		for _, swd := range sws.sections {
			if _, err := w.Write(swd.data); err != nil {
				return int(total), err
			}
		}
	}

	return int(total), nil
}

func newSegmentWithSections(segment * macho.Segment) * segmentWithSections {
	segment.Len = 72  // I think.. size of segment_command_64
	segData, err := segment.Data()
	if err != nil {
		return nil
	}
	return &segmentWithSections{
		segment: &segmentWithData{ segment, segData },
		sections: make([]sectionWithData, 0, 4),
	}
}

func (sws * segmentWithSections) addSectionWithData(swd * sectionWithData) {
	sws.sections = append(sws.sections, *swd)
	sws.segment.segment.Len += 80  // I think.. size of section64
}

func ForeachSectionInSegment(m * macho.File, segment * macho.Segment, visitor func (*macho.Section)) {
	for _, section := range m.Sections {
		if section.Seg == segment.Name {
			visitor(section)
		}
	}
}

type writeCounter int

func (w * writeCounter) Write(b []byte) (int, error) {
	*w += writeCounter(len(b))
	return len(b), nil
}

func writeSegment(w io.Writer, m * macho.Segment) error {
	s64 := &Segment64{
		LoadCmd: uint32(m.LoadCmd),
		Len: m.Len,
		Addr: m.Addr,
		Memsz: m.Memsz,
		Offset: m.Offset,
		Filesz: m.Filesz,
		Maxprot: uint32(m.Maxprot),
		Prot: uint32(m.Prot),
		Nsect: m.Nsect,
		Flag: uint32(m.Flag),
	}

	copy(s64.Name[:], m.Name)

	log.Infof("%16s: 0x%x - 0x%x (%x) [offset: 0x%x nsect: %d cmdlen: %d]",
		m.Name, s64.Addr, s64.Addr + s64.Memsz, s64.Memsz, s64.Offset, s64.Nsect, s64.Len)

	return binary.Write(w, binary.LittleEndian, s64)
}

func bugfixSectionToSection64(m * macho.Section) * Section64 {
	s64 := &Section64{
		Addr: m.Addr,
		Size: m.Size,
		Offset: m.Offset,
		Align: m.Align,
		Reloff: m.Reloff,
		Nreloc: m.Nreloc,
		Flags: uint32(m.Flags),
		Reserved1: 0,
		Reserved2: 0,
		Reserved3: 0,
	}

	copy(s64.Name[:], m.Name)
	copy(s64.Seg[:], m.Seg)

	return s64
}

func writeSection(w io.Writer, s64 * Section64) error {
	log.Infof("%16s: 0x%x - 0x%x (0x%x) [offset: 0x%x]",
		string(s64.Name[:]), s64.Addr, s64.Addr + uint64(s64.Size), s64.Size, s64.Offset)

	return binary.Write(w, binary.LittleEndian, s64)
}

type coalescedSectionWithMetrics struct {
	Section string
	Segment string
	Address uint64
	Size	uint64
	Metrics * coalesceMetrics
}

type namedCoalescedSectionWithMetrics struct {
	coalescedSectionWithMetrics
	Name string
}

type kextAnalyzer struct {
	kc * KernelCache
	cs []namedCoalescedSectionWithMetrics
	numCoalescedSections map[string]int
}

func (kc * KernelCache) NewKextAnalyzer() * kextAnalyzer {
	return &kextAnalyzer{
		kc: kc,
		cs: make([]namedCoalescedSectionWithMetrics, 0, 512),
		numCoalescedSections: make(map[string]int),
	}
}

func (ka * kextAnalyzer) AnalyzeKext(kext Kext) error {
	switch t := kext.(type) {
	case *CoalescedKext:
		for _, cs := range t.coalescedSections {
			ncs := namedCoalescedSectionWithMetrics{
				coalescedSectionWithMetrics: cs,
				Name: kext.Name(),
			}
			ka.cs = append(ka.cs, ncs)
		}
		ka.numCoalescedSections[kext.Name()] = len(t.coalescedSections)
	}

	return nil
}

type regionMap struct {
	used []byte
	start uint64
	nUsed uint64
	nOverlap uint64
	nMarked uint64
}

func newRegionMap(address, size uint64) * regionMap {
	return &regionMap{
		used: make([]byte, size),
		start: address,
	}
}

func (m * regionMap) markUsed(address, size uint64) {
	overlaps := false
	for i := address - m.start; i < size; i++ {
		if m.used[i] == 1 {
			overlaps = true
		} else {
			m.nUsed++
			m.used[i] = 1
		}
	}

	if overlaps {
		m.nOverlap++
	}

	m.nMarked++
}

func (m * regionMap) unusedBytesAfter(address, size uint64) (n uint64) {
	for i := int(address - m.start); i < len(m.used); i++ {
		if m.used[i] == 1 {
			break
		}
		n++
	}
	return
}

type counter64 struct {
	n uint64
	sum uint64
	zero uint64
}

func (c * counter64) add(n uint64) {
	c.n++
	c.sum += n
	if n == 0 {
		c.zero++
	}
}

func (ka * kextAnalyzer) DisplayResults() {
	/*
	 * Unreferenced regions/gaps:
	 *   Iterate over all of the coalesced sections, tracking the unreferenced regions
	 *   in each section.
	 */
	unreferencedRegions := make(map[string]regionMap)
	for _, cswm := range ka.cs {
		key := cswm.Segment + "," + cswm.Section
		regionMap, ok := unreferencedRegions[key]
		if !ok {
			regionMap = *newRegionMap(cswm.Metrics.address, cswm.Metrics.size)
		}

		regionMap.markUsed(cswm.Address, cswm.Size)

		unreferencedRegions[key] = regionMap
	}

	// Display stats about how many coalesced sections kexts have.
	sortedCounts := make([]int, 0, 8)
	groupedByCount := make(map[int]int)
	for _, numCS := range ka.numCoalescedSections {
		if num, ok := groupedByCount[numCS]; ok {
			groupedByCount[numCS] = num + 1
		} else {
			groupedByCount[numCS] = 1
		}
	}

	for count, _ := range groupedByCount {
		sortedCounts = append(sortedCounts, count)
	}

	sort.Ints(sortedCounts)

	fmt.Println()

	for _, count := range sortedCounts {
		fmt.Printf("%3d kexts had %d coalesced sections\n", groupedByCount[count], count)
	}

	fmt.Println()

	// Identify how much trailing unused space there is between each coalesced section.
	gapMetrics := make(map[string]*counter64)
	for _, cswm := range ka.cs {
		key := cswm.Segment + "," + cswm.Section
                regionMap, ok := unreferencedRegions[key]
		if !ok {
			panic("explode")
		}

		gap := regionMap.unusedBytesAfter(cswm.Address, cswm.Size)

		gapCounter, ok := gapMetrics[key]
		if !ok {
			gapCounter = new(counter64)
			gapMetrics[key] = gapCounter
		}

		gapCounter.add(gap)
	}

	for key, regionMap := range unreferencedRegions {
		fmt.Printf("%26s: Overlapping sections: %d\n", key, regionMap.nOverlap)
	}

	fmt.Println()

	for key, gapCounter := range gapMetrics {
		fmt.Printf("%26s: Contained sections: %3d Zero-sized gaps: %3d Avg Gap: 0x%x\n",
			key, gapCounter.n, gapCounter.zero, gapCounter.sum / gapCounter.n)
	}
}

