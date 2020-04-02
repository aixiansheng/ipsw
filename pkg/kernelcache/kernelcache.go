// +build linux,cgo darwin,cgo

package kernelcache

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/blacktop/go-macho"

	"github.com/apex/log"
	lzfse "github.com/blacktop/go-lzfse"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/lzss"
	"github.com/pkg/errors"
)

const (
	lzfseEncodeLSymbols       = 20
	lzfseEncodeMSymbols       = 20
	lzfseEncodeDSymbols       = 64
	lzfseEncodeLiteralSymbols = 256
	lzssPadding               = 0x16c
)

// Img4 Kernelcache object
type Img4 struct {
	IM4P    string
	Name    string
	Version string
	Data    []byte
}

// A LzssHeader represents the LZSS header
type LzssHeader struct {
	CompressionType  uint32 // 0x636f6d70 "comp"
	Signature        uint32 // 0x6c7a7373 "lzss"
	CheckSum         uint32 // Likely CRC32
	UncompressedSize uint32
	CompressedSize   uint32
	Padding          [lzssPadding]byte
}

// LzfseCompressedBlockHeaderV2 represents the lzfse header
type LzfseCompressedBlockHeaderV2 struct {
	Magic        uint32 // "bvx2"
	NumRawBytes  uint32
	PackedFields [3]uint64
	Freq         [2 * (lzfseEncodeLSymbols + lzfseEncodeMSymbols + lzfseEncodeDSymbols + lzfseEncodeLiteralSymbols)]uint8
}

// A CompressedCache represents an open compressed kernelcache file.
type CompressedCache struct {
	Magic  []byte
	Header interface{}
	Size   int
	Data   []byte
}

type PrelinkInfo struct {
	PrelinkInfoDictionary []CFBundle `plist:"_PrelinkInfoDictionary,omitempty"`
}

type CFBundle struct {
	Name                  string `plist:"CFBundleName,omitempty"`
	ID                    string `plist:"CFBundleIdentifier,omitempty"`
	InfoDictionaryVersion string `plist:"CFBundleInfoDictionaryVersion,omitempty"`
	CompatibleVersion     string `plist:"OSBundleCompatibleVersion,omitempty"`
	Version               string `plist:"CFBundleVersion,omitempty"`
	Required              string `plist:"OSBundleRequired,omitempty"`
	Executable            string `plist:"CFBundleExecutable,omitempty"`
	OSKernelResource      bool   `plist:"OSKernelResource,omitempty"`
	GetInfoString         string `plist:"CFBundleGetInfoString,omitempty"`
	AllowUserLoad         bool   `plist:"OSBundleAllowUserLoad,omitempty"`
	Signature             string `plist:"CFBundleSignature,omitempty"`
	PackageType           string `plist:"CFBundlePackageType,omitempty"`
	DevelopmentRegion     string `plist:"CFBundleDevelopmentRegion,omitempty"`
	ShortVersionString    string `plist:"CFBundleShortVersionString,omitempty"`
	ExecutableLoadAddr    uint64 `plist:"_PrelinkExecutableLoadAddr"`
}

func (pi *PrelinkInfo) ForeachBundle(visitor func(b * CFBundle) error) {
	for _, bundle := range pi.PrelinkInfoDictionary {
		bnd := bundle
		if visitor(&bnd) != nil {
			return
		}
	}
}

func fixUpPointer(imageBaseOffset, pointer uint64) uint64 {
	if pointer & 0xffffff0000000000 == 0xffffff0000000000 {
		return pointer
	}

	b63 := uint64(1 << 63)
	
	var result uint64
	if pointer & b63 != 0 {
		result = imageBaseOffset + (pointer & 0xffffffff)
	} else {
		result = ((pointer << 13) & 0xff00000000000000) | (pointer & 0x7ffffffffff);
		if (pointer & 0x40000000000) != 0 {
			result |= 0xfffc0000000000
		}
	}

	return result
}

/*
 * splitKCForeachKext iterates over kexts in a split kernel caches, where each kext's segments are
 * distinct.  Each kext dictionary listed in the prelink info dict will also contain the
 * ExecutableLoadAddr for the kext, revealing the address of its mach-o
 */
func (kc * KernelCache) splitKCForeachKext(visitor func(string, *macho.File, int64) error) error {
	plkDict, err := kc.PrelinkInfoDict()
	if err != nil {
		return err
	}

	plkDict.ForeachBundle(func(b * CFBundle) error {
		name := b.ID
		textBase := b.ExecutableLoadAddr

		if textBase == 0 {
			return fmt.Errorf("couldn't get ExecutableLoadAddr")
		}

		var visitorErr error

		// Find the Mach-O whose text segment's vmaddr equals the ExecutableLoadAddr.
		kc.ForeachMachO(func(m * macho.File, offset int64) error {
			if textSegment := m.SegmentByName("__TEXT"); textSegment != nil {
				if textSegment.Addr == textBase {
					visitorErr = visitor(name, m, offset)
					return io.EOF
				}
			}
			return nil
		})

		return visitorErr
	})

	return nil
}

func (kc * KernelCache) ForeachKModInfos(visitor func(pair * kModInfos) error) error {
	var err error
	if kc.kmodInfos == nil {
		if kc.kmodInfos, err = kc.populateKmodInfos(); err != nil {
			return err
		}
	}

	for _, n := range kc.kmodInfos {
		nfo := n
		if err = visitor(&nfo); err != nil {
			break;
		}
	}

	if err != io.EOF {
		return err
	}

	return nil
}

func (kc * KernelCache) populateKmodInfos() ([]kModInfos, error) {
	infos := make([]kModInfos, 0, 256)

	textBase := kc.GetTextBase()
	if textBase == 0 {
		return nil, fmt.Errorf("couldn't get kernel text segment base address")
	}

	kern := kc.GetKernelMachO()
	if kern == nil {
		return nil, fmt.Errorf("couldn't get kernel mach-o")
	}

	kernDataSeg := kern.SectionByName("__DATA", "__data")
	if kernDataSeg == nil {
		return nil, fmt.Errorf("couldn't get kernel __DATA __data")
	}

	kernDataSeg.Addr = fixUpPointer(textBase, kernDataSeg.Addr)

	kernData, err := kernDataSeg.Data()
	if err != nil {
		return nil, err
	}

	kmodStarts := kern.SectionByName("__PRELINK_INFO", "__kmod_start")
	kmodInfos := kern.SectionByName("__PRELINK_INFO", "__kmod_info")
	if kmodStarts == nil || kmodInfos == nil {
		return nil, fmt.Errorf("couldn't find kmod_starts or kmod_infos")
	}
	
	kmodStartsData, err := kmodStarts.Data()
	kmodInfosData, err := kmodInfos.Data()
	if kmodStartsData == nil || kmodInfosData == nil {
		return nil, fmt.Errorf("couldn't get data for kmod_starts or kmod_infos")
	}

	kmodStartsReader := bytes.NewReader(kmodStartsData)
	kmodInfosReader := bytes.NewReader(kmodInfosData)

	for {
		var kmodStartAddr uint64
		var kmodInfoAddr uint64
		if err = binary.Read(kmodStartsReader, binary.LittleEndian, &kmodStartAddr); err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}

		if err = binary.Read(kmodInfosReader, binary.LittleEndian, &kmodInfoAddr); err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}
		
		if kmodStartAddr == 0 || kmodInfoAddr == 0 {
			break
		}

		kmodStartAddr = fixUpPointer(textBase, kmodStartAddr)
		kmodInfoAddr = fixUpPointer(textBase, kmodInfoAddr)

		kmodInfos := kModInfos{
			kextAddr: kmodStartAddr,
			infoAddr: kmodInfoAddr,
		}

		kmodInfoStructOffset := kmodInfoAddr - kernDataSeg.Addr
		r := bytes.NewReader(kernData[kmodInfoStructOffset:])
		if err = binary.Read(r, binary.LittleEndian, &kmodInfos.info); err != nil {
			return nil, err
		}

		infos = append(infos, kmodInfos)
	}

	return infos, nil
}

/*
 * coalescedKCForeachKext iterates over kexts in coalesced caches, where the prelink info dict
 * won't contain the ExecutableLoadAddr and each kext will only have a distinct TEXT_EXEC segment
 * (all others are coalesced). Find the kext by iterating over the __PRELINK_INFO __kmod_start
 * addresses.
 */
func (kc * KernelCache) coalescedKCForeachKext(visitor func(string, *macho.File, int64) error) error {
	textBase := kc.GetTextBase()
	if textBase == 0 {
		return fmt.Errorf("couldn't get kernel text segment base address")
	}

	return kc.ForeachMachO(func(m * macho.File, offset int64) error {
		seg0 := m.Segments()[0]
		seg0Addr := fixUpPointer(textBase, seg0.Addr)

		foundMatchingKModInfo := false
		var visitorErr error
		err := kc.ForeachKModInfos(func(infos * kModInfos) error {
			if seg0Addr == infos.kextAddr {
				foundMatchingKModInfo = true
				visitorErr = visitor(string(bytes.Trim(infos.info.Name[:], "\x00")), m, offset)
				return io.EOF
			}
			return nil
		})

		if err != nil {
			return err
		}

		if !foundMatchingKModInfo && offset != 0 {
			log.Infof("couldn't find kModInfo matching mach-o at 0x%x", offset)
		}

		return visitorErr
	})
}

func (kc * KernelCache) ForeachKext(visitor func(string, *macho.File, int64) error) (err error) {
	if kc.Format == SplitCache {
		err = kc.splitKCForeachKext(visitor)
	} else {
		err = kc.coalescedKCForeachKext(visitor)
	}

	if err == io.EOF {
		err = nil
	}

	return
}

func (kc * KernelCache) KextWithName(kextName string) (kext * macho.File, err error) {
	err = kc.ForeachKext(func(name string, kxt * macho.File, offset int64) error {
		if name == kextName {
			kext = kxt
			return io.EOF
		}
		return nil
	})

	if err != nil {
		return
	}

	if kext == nil {
		err = fmt.Errorf("couldn't find specified kext")
	}

	return
}

type addressOffsetPair struct {
	address	uint64
	offset	uint64
}

type prelinkOffsets struct {
	prelinkText		addressOffsetPair
	prelinkTextExec		addressOffsetPair
	prelinkData		addressOffsetPair
	prelinkDataConst	addressOffsetPair
	prelinkLinkEdit		addressOffsetPair
	prelinkInfo		addressOffsetPair
}

func addressOffsetPairForSegment(seg * macho.Segment) addressOffsetPair {
	return addressOffsetPair{
		address: seg.Addr,
		offset: seg.Offset,
	}
}

type KernelCacheFormat byte

const (
	SplitCache KernelCacheFormat = iota
	CoalescedDataCache
)

type kModInfo struct {
	NextAddr uint64
	InfoVersion uint32
	Id uint32
	Name [64]byte
	Version [64]byte
	ReferenceCount uint32
	ReferenceListAddr uint64
	Address uint64
	Size uint64
	HeaderSize uint64
	StartAddr uint64
	StopAddr uint64
}

type kModInfos struct {
	kextAddr uint64
	infoAddr uint64
	info kModInfo
}

type KernelCache struct {
	r *os.File
	plkOffsets * prelinkOffsets
	plkDict * PrelinkInfo
	textBase uint64
	kernelMachO * macho.File
	Format KernelCacheFormat
	kmodInfos []kModInfos
}

func (kc * KernelCache) Close() {
	kc.r.Close()
}

func (kc * KernelCache) Reader() *os.File {
	return kc.r
}

func (kc * KernelCache) GetKernelMachO() *macho.File {
	if kc.kernelMachO == nil {
		kc.ForeachMachO(func(m * macho.File, offset int64) error {
			if m.SegmentByName("__PRELINK_INFO") != nil {
				kc.kernelMachO = m
				return io.EOF
			}
			return nil
		})
	}

	return kc.kernelMachO
}

func (kc * KernelCache) GetTextBase() uint64 {
	if kc.textBase == 0 {
		kc.ForeachMachO(func(m * macho.File, offset int64) error {
			// Not sure if this logic is correct..
			if textSeg := m.SegmentByName("__TEXT"); textSeg != nil {
				kc.textBase = textSeg.Addr
			}
			return io.EOF
		})
	}

	return kc.textBase
}

func (kc * KernelCache) MainKernelSegments() ([]*macho.Segment, error) {
	var segs []*macho.Segment
	kc.ForeachMachO(func(m * macho.File, offset int64) error {
		segs = m.Segments()
		return io.EOF
	})
	
	if segs != nil {
		return segs, nil
	} else {
		return nil, fmt.Errorf("Couldn't find kernel segments")
	}
}

func NewKernelCache(cache string) (*KernelCache, error) {
	kc := &KernelCache{}
	
	f, err := os.Open(cache)
	if err != nil {
		return nil, err
	}

	kc.r = f

	// Newer kernel caches have a __TEXT __info_plist section.
	hasTestInfoPlist := false
	kc.ForeachMachO(func(m * macho.File, offset int64) error {
		if m.SectionByName("__TEXT", "__info_plist") != nil {
			hasTestInfoPlist = true
		}
		return io.EOF
	})

	if hasTestInfoPlist {
		kc.Format = CoalescedDataCache
	} else {
		kc.Format = SplitCache
	}

	return kc, nil
}

func (kc * KernelCache) PrelinkOffsets() (*prelinkOffsets, error) {
	if kc.plkOffsets != nil {
		return kc.plkOffsets, nil
	}

	textBase := kc.GetTextBase()
	if textBase == 0 {
		return nil, fmt.Errorf("Couldn't get text base")
	}

	ra := io.NewSectionReader(kc.r, 0, 1<<63-1)
	kernelMachO, err := macho.NewFile(ra)
	if err != nil {
		return nil, err
	}

	var offsets prelinkOffsets

	for _, seg := range kernelMachO.Segments() {
		var pair *addressOffsetPair

		switch seg.Name {
		case "__PRELINK_TEXT":
			pair = &offsets.prelinkText
		case "__PRELINK_INFO":
			pair = &offsets.prelinkInfo
		case "__PLK_TEXT_EXEC":
			pair = &offsets.prelinkTextExec
		case "__PRELINK_DATA":
			pair = &offsets.prelinkData
		case "__PLK_DATA_CONST":
			pair = &offsets.prelinkDataConst
		case "__PLK_LINKEDIT":
			pair = &offsets.prelinkLinkEdit
		}

		if nil != pair {
			*pair = addressOffsetPairForSegment(seg)
			pair.address = fixUpPointer(textBase, pair.address)
			log.Debugf("Prelink %16s: 0x%.16x : 0x%x", seg.Name, pair.address, pair.offset)
		}
	}

	kc.plkOffsets = &offsets

	return &offsets, nil
}

func (kc * KernelCache) PrelinkInfoDict() (*PrelinkInfo, error) {
	if kc.plkDict != nil {
		return kc.plkDict, nil
	}

	ra := io.NewSectionReader(kc.r, 0, 1<<63-1)
	kernelMachO, err := macho.NewFile(ra)
	if err != nil {
		return nil, err
	}

	sect := kernelMachO.SectionByName("__PRELINK_INFO", "__info")
	if sect == nil {
		return nil, fmt.Errorf("No prelink section")
	}

	f := sect.Open()

	data := make([]byte, sect.Size)
	_, err = f.Read(data)
	if err != nil {
		return nil, err
	}

	var prelink PrelinkInfo
	decoder := plist.NewDecoder(bytes.NewReader(bytes.Trim([]byte(data), "\x00")))
	err = decoder.Decode(&prelink)
	if err != nil {
		return nil, err
	}

	kc.plkDict = &prelink

	return &prelink, nil
}

// SlideOffset slides an offset from a segment of the given its name and address.  Slide must be added
// to each segment of a kext because without it, their offsets won't be accurate.
func (offsets * prelinkOffsets) SlideOffset(segname string, addr uint64) uint64 {
	pair := &addressOffsetPair{}

	switch segname {
	case "__TEXT":
		pair = &offsets.prelinkText
	case "__TEXT_EXEC":
		pair = &offsets.prelinkTextExec
	case "__DATA":
		pair = &offsets.prelinkData
	case "__DATA_CONST":
		pair = &offsets.prelinkDataConst
	}

	//fmt.Printf("Sliding offset: 0x%x - 0x%x + 0x%x\n", pair.offset, pair.address, addr)
	return pair.offset - pair.address + addr
}

func (kc * KernelCache) ForeachMachO(visitor func(*macho.File, int64) error) error {
	r := io.NewSectionReader(kc.r, 0, 1<<63-1)
	for {
		var magic uint32
		err := binary.Read(r, binary.LittleEndian, &magic)
		if err != nil {
			return err
		}

		if magic != 0xfeedfacf {
			continue
		}

		seek, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}

		r2 := io.NewSectionReader(r, seek - 4, 1<<63-1)
		m, err := macho.NewFile(r2)

		if _, err2 := kc.r.Seek(seek + 32, io.SeekStart); err2 != nil {
			return err2
		}

		if err == nil {
			err = visitor(m, seek - 4)
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
	}
}

// ParseImg4Data parses a img4 data containing a compressed kernelcache.
func ParseImg4Data(data []byte) (*CompressedCache, error) {
	utils.Indent(log.Info, 2)("Parsing Kernelcache IMG4")

	// NOTE: openssl asn1parse -i -inform DER -in kernelcache.iphone10 | less (to get offset)
	//       openssl asn1parse -i -inform DER -in kernelcache.iphone10 -strparse OFFSET -noout -out lzfse.bin
	var i Img4
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Kernelcache")
	}

	cc := CompressedCache{
		Magic: make([]byte, 4),
		Size:  len(i.Data),
		Data:  i.Data,
	}

	// Read file header magic.
	if err := binary.Read(bytes.NewBuffer(i.Data[:4]), binary.BigEndian, &cc.Magic); err != nil {
		return nil, err
	}

	return &cc, nil
}

// Extract extracts and decompresses a lernelcache from ipsw
func Extract(ipsw string) error {
	log.Info("Extracting Kernelcache from IPSW")
	kcaches, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		if strings.Contains(f.Name, "kernelcache") {
			return true
		}
		return false
	})
	if err != nil {
		return errors.Wrap(err, "failed extract kernelcache from ipsw")
	}
	i, err := info.Parse(ipsw)
	if err != nil {
		return errors.Wrap(err, "failed to parse ipsw info")
	}
	for _, kcache := range kcaches {
		content, err := ioutil.ReadFile(kcache)
		if err != nil {
			return errors.Wrap(err, "failed to read Kernelcache")
		}

		kc, err := ParseImg4Data(content)
		if err != nil {
			return errors.Wrap(err, "failed parse compressed kernelcache")
		}

		dec, err := DecompressData(kc)
		if err != nil {
			return errors.Wrap(err, "failed to decompress kernelcache")
		}
		for _, folder := range i.GetKernelCacheFolders(kcache) {
			os.Mkdir(folder, os.ModePerm)
			fname := filepath.Join(folder, "kernelcache."+strings.ToLower(i.Plists.GetOSType()))
			err = ioutil.WriteFile(fname, dec, 0644)
			if err != nil {
				return errors.Wrap(err, "failed to decompress kernelcache")
			}
			utils.Indent(log.Info, 2)("Created " + fname)
			os.Remove(kcache)
		}
	}

	return nil
}

// Decompress decompresses a compressed kernelcache
func Decompress(kcache string) error {
	content, err := ioutil.ReadFile(kcache)
	if err != nil {
		return errors.Wrap(err, "failed to read Kernelcache")
	}

	kc, err := ParseImg4Data(content)
	if err != nil {
		return errors.Wrap(err, "failed parse compressed kernelcache")
	}
	// defer os.Remove(kcache)

	utils.Indent(log.Info, 2)("Decompressing Kernelcache")
	dec, err := DecompressData(kc)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}

	err = ioutil.WriteFile(kcache+".decompressed", dec, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}
	utils.Indent(log.Info, 2)("Created " + kcache + ".decompressed")
	return nil
}

// DecompressData decompresses compressed kernelcache []byte data
func DecompressData(cc *CompressedCache) ([]byte, error) {
	utils.Indent(log.Info, 2)("Decompressing Kernelcache")

	if bytes.Contains(cc.Magic, []byte("bvx2")) { // LZFSE
		utils.Indent(log.Info, 2)("Kernelcache is LZFSE compressed")
		lzfseHeader := LzfseCompressedBlockHeaderV2{}
		// Read entire file header.
		if err := binary.Read(bytes.NewBuffer(cc.Data[:1000]), binary.BigEndian, &lzfseHeader); err != nil {
			return nil, err
		}
		cc.Header = lzfseHeader

		decData := lzfse.DecodeBuffer(cc.Data)

		fat, err := macho.NewFatFile(bytes.NewReader(decData))
		if errors.Is(err, macho.ErrNotFat) {
			return decData, nil
		}
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse fat mach-o")
		}
		defer fat.Close()

		// Sanity check
		if len(fat.Arches) > 1 {
			return nil, errors.New("found more than 1 mach-o fat file")
		}

		// Essentially: lipo -thin arm64e
		return decData[fat.Arches[0].Offset:], nil

	} else if bytes.Contains(cc.Magic, []byte("comp")) { // LZSS
		utils.Indent(log.Debug, 1)("kernelcache is LZSS compressed")
		buffer := bytes.NewBuffer(cc.Data)
		lzssHeader := LzssHeader{}
		// Read entire file header.
		if err := binary.Read(buffer, binary.BigEndian, &lzssHeader); err != nil {
			return nil, err
		}

		msg := fmt.Sprintf("compressed size: %d, uncompressed: %d. checkSum: 0x%x",
			lzssHeader.CompressedSize,
			lzssHeader.UncompressedSize,
			lzssHeader.CheckSum,
		)
		utils.Indent(log.Debug, 1)(msg)

		cc.Header = lzssHeader

		if int(lzssHeader.CompressedSize) > cc.Size {
			return nil, fmt.Errorf("compressed_size: %d is greater than file_size: %d", cc.Size, lzssHeader.CompressedSize)
		}

		// Read compressed file data.
		cc.Data = buffer.Next(int(lzssHeader.CompressedSize))
		dec := lzss.Decompress(cc.Data)
		return dec[:lzssHeader.UncompressedSize], nil
	}

	return []byte{}, errors.New("unsupported compression")
}

// RemoteParse parses plist files in a remote ipsw file
func RemoteParse(zr *zip.Reader) error {

	ipsw, err := info.ParseZipFiles(zr.File)
	if err != nil {
		return err
	}

	for _, f := range zr.File {
		if strings.Contains(f.Name, "kernelcache.") {
			for _, folder := range ipsw.GetKernelCacheFolders(f.Name) {
				fname := filepath.Join(folder, "kernelcache."+strings.ToLower(ipsw.Plists.GetOSType()))
				if _, err := os.Stat(fname); os.IsNotExist(err) {
					kdata := make([]byte, f.UncompressedSize64)
					rc, err := f.Open()
					if err != nil {
						return errors.Wrapf(err, "failed to open file in zip: %s", f.Name)
					}
					io.ReadFull(rc, kdata)
					rc.Close()

					kcomp, err := ParseImg4Data(kdata)
					if err != nil {
						return errors.Wrap(err, "failed parse compressed kernelcache")
					}

					dec, err := DecompressData(kcomp)
					if err != nil {
						return errors.Wrap(err, "failed to decompress kernelcache")
					}

					os.Mkdir(folder, os.ModePerm)
					err = ioutil.WriteFile(fname, dec, 0644)
					if err != nil {
						return errors.Wrap(err, "failed to decompress kernelcache")
					}
				} else {
					log.Warnf("kernelcache already exists: %s", fname)
				}
			}
		}
	}

	return nil
}
