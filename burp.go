package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

const burpHeaderSize = 72
const burpMagic uint32 = 0x66858280
const burpCompatibility int32 = -2142078604 // 0x80527974
const maxOuterVersion int32 = 1

var (
	methodNames      = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
	methodGroup      = strings.Join(methodNames, "|")
	requestSearchRE  = regexp.MustCompile(`(` + methodGroup + `) [^\r\n \x00]{1,1000} HTTP/(1\.[01]|2)\r?\n`)
	requestStartRE   = regexp.MustCompile(`^(` + methodGroup + `) [^\r\n \x00]{1,1000} HTTP/(1\.[01]|2)\r?\n`)
	responseSearchRE = regexp.MustCompile(`HTTP/(1\.[01]|2) [0-9]{3}[^\r\n]{0,200}\r?\n`)
	collaboratorRE   = regexp.MustCompile(`(?i)[a-z0-9]{16,40}\.(oastify\.com|burpcollaborator\.net|oast\.(fun|pro|live|site|online|me))`)
)

var highlightColors = map[byte]string{
	0: "none", 1: "red", 2: "orange", 3: "yellow", 4: "green",
	5: "cyan", 6: "blue", 7: "pink", 8: "magenta", 9: "gray",
}

var burpMIME = map[int16]string{
	0x0100: "HTML", 0x0101: "TEXT", 0x0102: "CSS", 0x0103: "SCRIPT",
	0x0104: "JSON", 0x0106: "XML",
}

type BurpFormatError struct {
	Message string
}

func (e BurpFormatError) Error() string { return e.Message }

func catchFormat(fn func()) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			switch value := recovered.(type) {
			case BurpFormatError:
				err = value
			case *BurpFormatError:
				err = *value
			default:
				panic(recovered)
			}
		}
	}()
	fn()
	return nil
}

type BurpHeader struct {
	Magic            uint32
	OuterVersion     int32
	Compatibility    int32
	SchemaFloor      uint16
	SchemaCurrent    uint16
	RandomIdentifier uint32
	MetadataRoot     int64
	SegmentSpan      int64
	AllocationCursor int64
	ProjectRoot      int64
	FileSize         int
}

type BurpObject struct {
	Address int64
	Type    byte
	Subtype byte
	Flags   byte
	Fields  map[byte]int16
}

type BurpProject struct {
	Data     []byte
	Header   BurpHeader
	progress *progressBar
}

func NewBurpProjectFromBytes(data []byte) (*BurpProject, error) {
	project := &BurpProject{Data: data}
	header, err := project.parseHeader()
	if err != nil {
		return nil, err
	}
	project.Header = header
	return project, nil
}

func (p *BurpProject) fail(format string, args ...any) {
	panic(BurpFormatError{Message: fmt.Sprintf(format, args...)})
}

func (p *BurpProject) report(label string, percent float64) {
	if p.progress != nil {
		p.progress.Update(label, percent)
	}
}

func (p *BurpProject) need(offset int64, size int64) {
	if offset < 0 || size < 0 || offset+size > int64(len(p.Data)) {
		p.fail("read at %d+%d exceeds project data", offset, size)
	}
}

func (p *BurpProject) u8(offset int64) byte {
	p.need(offset, 1)
	return p.Data[offset]
}

func (p *BurpProject) i16(offset int64) int16 {
	p.need(offset, 2)
	return int16(binary.BigEndian.Uint16(p.Data[offset:]))
}

func (p *BurpProject) u16(offset int64) uint16 {
	p.need(offset, 2)
	return binary.BigEndian.Uint16(p.Data[offset:])
}

func (p *BurpProject) i32(offset int64) int32 {
	p.need(offset, 4)
	return int32(binary.BigEndian.Uint32(p.Data[offset:]))
}

func (p *BurpProject) i64(offset int64) int64 {
	p.need(offset, 8)
	return int64(binary.BigEndian.Uint64(p.Data[offset:]))
}

func (p *BurpProject) parseHeader() (BurpHeader, error) {
	if len(p.Data) < burpHeaderSize {
		return BurpHeader{}, BurpFormatError{"project is smaller than the 72-byte header"}
	}
	magic := binary.BigEndian.Uint32(p.Data[0:])
	outerVersion := int32(binary.BigEndian.Uint32(p.Data[4:]))
	compatibility := int32(binary.BigEndian.Uint32(p.Data[8:]))
	if magic != burpMagic {
		return BurpHeader{}, BurpFormatError{fmt.Sprintf("invalid project magic 0x%08x", magic)}
	}
	if outerVersion < 0 || outerVersion > maxOuterVersion {
		return BurpHeader{}, BurpFormatError{fmt.Sprintf("unsupported outer version %d", outerVersion)}
	}
	if compatibility > burpCompatibility {
		return BurpHeader{}, BurpFormatError{fmt.Sprintf("unsupported compatibility value %d", compatibility)}
	}
	schemaFloor := binary.BigEndian.Uint16(p.Data[12:])
	schemaCurrent := binary.BigEndian.Uint16(p.Data[14:])
	randomID := binary.BigEndian.Uint32(p.Data[16:])
	metadataRoot := int64(binary.BigEndian.Uint64(p.Data[40:]))
	span := int64(binary.BigEndian.Uint64(p.Data[48:]))
	cursor := int64(binary.BigEndian.Uint64(p.Data[56:]))
	projectRoot := int64(binary.BigEndian.Uint64(p.Data[64:]))
	if span <= 0 || cursor < burpHeaderSize || metadataRoot < 0 || projectRoot < 0 {
		return BurpHeader{}, BurpFormatError{"invalid header roots or allocation cursor"}
	}
	if cursor > int64(len(p.Data)) {
		return BurpHeader{}, BurpFormatError{fmt.Sprintf("allocation cursor %d exceeds file size %d", cursor, len(p.Data))}
	}
	return BurpHeader{
		Magic: magic, OuterVersion: outerVersion, Compatibility: compatibility,
		SchemaFloor: schemaFloor, SchemaCurrent: schemaCurrent, RandomIdentifier: randomID,
		MetadataRoot: metadataRoot, SegmentSpan: span, AllocationCursor: cursor,
		ProjectRoot: projectRoot, FileSize: len(p.Data),
	}, nil
}

func (p *BurpProject) parseObject(address int64, maxDepth int) *BurpObject {
	visited := map[int64]bool{}
	current := address
	for depth := 0; depth <= maxDepth; depth++ {
		if visited[current] {
			p.fail("forwarding cycle at %d", current)
		}
		visited[current] = true
		p.need(current, 4)
		flags := p.Data[current]
		if flags&1 != 0 {
			forward := p.i64(current + 1)
			if forward <= 0 {
				p.fail("invalid forwarding address %d", forward)
			}
			current = forward
			continue
		}
		typeID := p.Data[current+1]
		subtype := p.Data[current+2]
		count := int(p.Data[current+3])
		p.need(current, int64(4+count*3))
		fields := make(map[byte]int16, count)
		previous := int16(4 + count*3 - 1)
		for index := 0; index < count; index++ {
			entry := current + 4 + int64(index)*3
			fieldID := p.u8(entry)
			rel := p.i16(entry + 1)
			if fieldID >= 128 {
				p.fail("invalid field id %d", fieldID)
			}
			if _, exists := fields[fieldID]; exists {
				p.fail("duplicate field id %d", fieldID)
			}
			if rel < int16(4+count*3) || rel <= previous {
				p.fail("bad field offset for id %d", fieldID)
			}
			previous = rel
			fields[fieldID] = rel
		}
		for _, rel := range fields {
			if current+int64(rel) >= int64(len(p.Data)) {
				p.fail("field address outside project")
			}
		}
		return &BurpObject{Address: current, Type: typeID, Subtype: subtype, Flags: flags, Fields: fields}
	}
	p.fail("forwarding depth exceeded at %d", address)
	return nil
}

func (p *BurpProject) fieldOffset(obj *BurpObject, fieldID byte) (int64, bool) {
	rel, ok := obj.Fields[fieldID]
	if !ok {
		return 0, false
	}
	return obj.Address + int64(rel), true
}

func (p *BurpProject) readAddress(obj *BurpObject, fieldID byte) int64 {
	offset, ok := p.fieldOffset(obj, fieldID)
	if !ok {
		return 0
	}
	value := p.i64(offset)
	if value < 0 {
		p.fail("negative address in field %d", fieldID)
	}
	if value == 0 {
		return 0
	}
	return value
}

func (p *BurpProject) tryReadAddress(obj *BurpObject, fieldID byte) (value int64) {
	_ = catchFormat(func() { value = p.readAddress(obj, fieldID) })
	return value
}

func (p *BurpProject) readI32(obj *BurpObject, fieldID byte) *int {
	offset, ok := p.fieldOffset(obj, fieldID)
	if !ok {
		return nil
	}
	value := int(p.i32(offset))
	return &value
}

func (p *BurpProject) readI64(obj *BurpObject, fieldID byte) *int64 {
	offset, ok := p.fieldOffset(obj, fieldID)
	if !ok {
		return nil
	}
	value := p.i64(offset)
	return &value
}

func (p *BurpProject) readI16(obj *BurpObject, fieldID byte) *int {
	offset, ok := p.fieldOffset(obj, fieldID)
	if !ok {
		return nil
	}
	value := int(p.i16(offset))
	return &value
}

func (p *BurpProject) readU8(obj *BurpObject, fieldID byte) *byte {
	offset, ok := p.fieldOffset(obj, fieldID)
	if !ok {
		return nil
	}
	value := p.u8(offset)
	return &value
}

func (p *BurpProject) variableRecord(address int64) []byte {
	if address == 0 {
		p.fail("null record address")
	}
	p.need(address, 8)
	total := p.i32(address)
	logical := p.i32(address + 4)
	if logical < 0 {
		p.fail("negative record length at %d", address)
	}
	expected := int32(8 + maxInt(int(logical), 1))
	if total != expected {
		p.fail("record at %d has total %d, expected %d", address, total, expected)
	}
	p.need(address+8, int64(logical))
	return p.Data[address+8 : address+8+int64(logical)]
}

func (p *BurpProject) variableArray(address int64, elementSize int) (int, []byte) {
	if address == 0 {
		p.fail("null array address")
	}
	if elementSize <= 0 {
		p.fail("invalid element size")
	}
	p.need(address, 8)
	total := p.i32(address)
	count := p.i32(address + 4)
	if count < 0 {
		p.fail("negative array count at %d", address)
	}
	payloadSize := int64(count) * int64(elementSize)
	expected := int32(8 + maxInt(int(payloadSize), 1))
	if total != expected {
		p.fail("array at %d has total %d, expected %d", address, total, expected)
	}
	p.need(address+8, payloadSize)
	return int(count), p.Data[address+8 : address+8+payloadSize]
}

func (p *BurpProject) addressArray(address int64) []int64 {
	count, payload := p.variableArray(address, 8)
	out := make([]int64, 0, count)
	for index := 0; index < count; index++ {
		value := int64(binary.BigEndian.Uint64(payload[index*8:]))
		if value < 0 {
			p.fail("negative address in address array")
		}
		if value == 0 {
			out = append(out, 0)
		} else {
			out = append(out, value)
		}
	}
	return out
}

func (p *BurpProject) textFrame(address int64) string {
	count, payload := p.variableArray(address, 2)
	units := make([]uint16, count)
	for index := 0; index < count; index++ {
		units[index] = binary.BigEndian.Uint16(payload[index*2:])
	}
	return string(utf16.Decode(units))
}

func (p *BurpProject) immutableString(address int64) *string {
	if address == 0 {
		return nil
	}
	obj := p.parseObject(address, 16)
	chars := p.readAddress(obj, 0)
	if chars == 0 {
		return nil
	}
	text := p.textFrame(chars)
	return &text
}

func (p *BurpProject) textWrapper(address int64) *string {
	if address == 0 {
		return nil
	}
	obj := p.parseObject(address, 16)
	for _, fieldID := range []byte{0, 1, 2} {
		chars := p.readAddress(obj, fieldID)
		if chars == 0 {
			continue
		}
		var text string
		err := catchFormat(func() { text = p.textFrame(chars) })
		if err != nil {
			continue
		}
		printable := true
		for _, r := range text {
			if r != '\t' && r != '\n' && r != '\r' && r < ' ' {
				printable = false
				break
			}
		}
		if text != "" && printable {
			return &text
		}
	}
	return nil
}

func (p *BurpProject) mutableString(address int64) *string {
	if address == 0 {
		return nil
	}
	var result *string
	err := catchFormat(func() {
		obj := p.parseObject(address, 16)
		length := p.readI32(obj, 0)
		chunksAddress := p.readAddress(obj, 3)
		if length == nil || chunksAddress == 0 {
			result = p.immutableString(address)
			return
		}
		chunks := p.directCollection(chunksAddress)
		var builder strings.Builder
		for _, chunk := range chunks {
			if chunk != 0 {
				builder.WriteString(p.textFrame(chunk))
			}
		}
		text := builder.String()
		if *length >= 0 {
			runes := []rune(text)
			if *length < len(runes) {
				runes = runes[:*length]
			}
			text = string(runes)
		}
		result = &text
	})
	if err != nil {
		return p.immutableString(address)
	}
	return result
}

func (p *BurpProject) directCollection(address int64) []int64 {
	obj := p.parseObject(address, 16)
	size := p.readI32(obj, 0)
	backing := p.readAddress(obj, 1)
	if size == nil || backing == 0 {
		p.fail("direct collection missing size or backing array")
	}
	addresses := p.addressArray(backing)
	if *size > len(addresses) {
		p.fail("direct collection size exceeds backing array")
	}
	return addresses[:*size]
}

func (p *BurpProject) chunkedCollection(address int64) []int64 {
	obj := p.parseObject(address, 16)
	size := p.readI32(obj, 0)
	chunkSize := p.readI32(obj, 1)
	chunkListAddress := p.readAddress(obj, 2)
	leading := p.readI32(obj, 3)
	if size == nil || chunkSize == nil || chunkListAddress == 0 || leading == nil {
		p.fail("chunked collection is missing a required field")
	}
	if *size < 0 || *chunkSize <= 0 || *leading < 0 {
		p.fail("invalid chunked collection dimensions")
	}
	chunkList := p.parseObject(chunkListAddress, 16)
	chunkCount := p.readI32(chunkList, 0)
	arrayAddress := p.readAddress(chunkList, 1)
	if chunkCount == nil || arrayAddress == 0 {
		p.fail("chunk list is missing a required field")
	}
	chunkAddresses := p.addressArray(arrayAddress)
	if *chunkCount > len(chunkAddresses) {
		p.fail("chunk count exceeds address array")
	}
	cache := map[int64][]int64{}
	out := make([]int64, 0, *size)
	for logical := 0; logical < *size; logical++ {
		physical := *leading + logical
		chunkIndex := physical / *chunkSize
		slot := physical % *chunkSize
		if chunkIndex >= *chunkCount {
			p.fail("missing chunk %d", chunkIndex)
		}
		chunkAddress := chunkAddresses[chunkIndex]
		if chunkAddress == 0 {
			p.fail("null chunk address")
		}
		slots, ok := cache[chunkAddress]
		if !ok {
			slots = p.addressArray(chunkAddress)
			cache[chunkAddress] = slots
		}
		if slot >= len(slots) {
			p.fail("slot outside chunk")
		}
		out = append(out, slots[slot])
	}
	return out
}

func (p *BurpProject) uuidObject(address int64) *string {
	if address == 0 {
		return nil
	}
	obj := p.parseObject(address, 16)
	high := p.readI64(obj, 0)
	low := p.readI64(obj, 1)
	if high == nil || low == nil {
		return nil
	}
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[0:], uint64(*high))
	binary.BigEndian.PutUint64(raw[8:], uint64(*low))
	text := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
	return &text
}

func (p *BurpProject) service(row *BurpObject) *Service {
	metadataAddress := p.readAddress(row, 2)
	if metadataAddress == 0 {
		return nil
	}
	metadata := p.parseObject(metadataAddress, 16)
	serviceAddress := p.readAddress(metadata, 0)
	if serviceAddress == 0 {
		return nil
	}
	serviceObj := p.parseObject(serviceAddress, 16)
	hostWrapperAddress := p.readAddress(serviceObj, 0)
	host := ""
	if hostWrapperAddress != 0 {
		wrapper := p.parseObject(hostWrapperAddress, 16)
		textAddress := p.readAddress(wrapper, 0)
		if textAddress != 0 {
			host = p.textFrame(textAddress)
		}
	}
	port := p.readI32(serviceObj, 1)
	var tls *bool
	if value := p.readU8(serviceObj, 2); value != nil {
		enabled := *value != 0
		tls = &enabled
	}
	return &Service{
		Host: host, Port: port, TLS: tls,
		RequestMetadataAddress: metadataAddress,
		ServiceAddress:         serviceAddress,
	}
}

func (p *BurpProject) comment(row *BurpObject) *string {
	for _, fieldID := range []byte{3, 27} {
		address := p.readAddress(row, fieldID)
		if address == 0 {
			continue
		}
		if text := p.textWrapper(address); text != nil {
			return text
		}
		var wrapper *BurpObject
		if err := catchFormat(func() { wrapper = p.parseObject(address, 16) }); err != nil {
			continue
		}
		current := p.tryReadAddress(wrapper, 2)
		if current == 0 {
			current = p.tryReadAddress(wrapper, 1)
		}
		seen := map[int64]bool{}
		parts := []string{}
		for current != 0 && !seen[current] && len(seen) < 10_000 {
			seen[current] = true
			var value string
			err := catchFormat(func() {
				chunk := p.parseObject(current, 16)
				textAddress := p.readAddress(chunk, 1)
				length := p.readI32(chunk, 2)
				if textAddress != 0 {
					value = p.textFrame(textAddress)
					if length != nil {
						runes := []rune(value)
						if *length >= 0 && *length < len(runes) {
							runes = runes[:*length]
						}
						value = string(runes)
					}
					parts = append(parts, value)
				}
				current = p.readAddress(chunk, 3)
			})
			if err != nil {
				break
			}
		}
		if len(parts) > 0 {
			text := strings.Join(parts, "")
			return &text
		}
	}
	return nil
}

func (p *BurpProject) row(address int64) map[string]any {
	obj := p.parseObject(address, 16)
	meta := map[string]any{
		"entry_id":                p.readI32(obj, 0),
		"method_hint":             p.immutableString(p.readAddress(obj, 1)),
		"ip":                      p.immutableString(p.readAddress(obj, 4)),
		"status":                  p.readI16(obj, 6),
		"burp_mime":               nil,
		"title":                   p.immutableString(p.readAddress(obj, 9)),
		"cookie_header":           p.immutableString(p.readAddress(obj, 10)),
		"time_epoch_ms":           p.readI64(obj, 11),
		"listener_port":           p.readI32(obj, 14),
		"comment":                 p.comment(obj),
		"service":                 p.service(obj),
		"timing_1":                p.readI64(obj, 28),
		"timing_2":                p.readI64(obj, 29),
		"secondary_time_epoch_ms": p.readI64(obj, 30),
		"row_address":             address,
	}
	mimeCode := p.readI16(obj, 7)
	meta["burp_mime_code"] = mimeCode
	if mimeCode != nil {
		if name, ok := burpMIME[int16(*mimeCode)]; ok {
			meta["burp_mime"] = name
		}
	}
	meta["response_length"] = p.readI32(obj, 8)
	highlight := "none"
	if value := p.readU8(obj, 13); value != nil {
		if name, ok := highlightColors[*value]; ok {
			highlight = name
		} else {
			highlight = "unknown"
		}
	}
	meta["highlight"] = highlight
	return meta
}

func (p *BurpProject) firstAddress(obj *BurpObject, fields []byte) int64 {
	for _, fieldID := range fields {
		if address := p.readAddress(obj, fieldID); address != 0 {
			return address
		}
	}
	return 0
}

func (p *BurpProject) extractProxy(warnings *[]string) []*Exchange {
	p.report("Extracting Proxy history", 20)
	root := p.parseObject(p.Header.ProjectRoot, 16)
	proxyAddress := p.readAddress(root, 1)
	if proxyAddress == 0 {
		return []*Exchange{}
	}
	proxy := p.parseObject(proxyAddress, 16)
	seen := map[int64]bool{}
	out := []*Exchange{}
	for collectionField := byte(0); collectionField <= 1; collectionField++ {
		collectionAddress := p.readAddress(proxy, collectionField)
		if collectionAddress == 0 {
			continue
		}
		var items []int64
		if err := catchFormat(func() { items = p.chunkedCollection(collectionAddress) }); err != nil {
			*warnings = append(*warnings, fmt.Sprintf("Proxy collection %d could not be decoded: %s", collectionField, err))
			continue
		}
		for itemIndex, itemAddress := range items {
			if len(items) > 0 {
				p.report("Extracting Proxy history", 20+6*float64(collectionField)+
					6*float64(itemIndex+1)/float64(len(items)))
			}
			if itemAddress == 0 || seen[itemAddress] {
				continue
			}
			seen[itemAddress] = true
			var exchange *Exchange
			err := catchFormat(func() {
				row := p.parseObject(itemAddress, 16)
				requestAddress := p.firstAddress(row, []byte{15, 16, 17})
				responseAddress := p.firstAddress(row, []byte{18, 19, 20})
				var requestRaw, responseRaw []byte
				if requestAddress != 0 {
					requestRaw = p.variableRecord(requestAddress)
				}
				if responseAddress != 0 {
					responseRaw = p.variableRecord(responseAddress)
				}
				if len(requestRaw) == 0 && len(responseRaw) == 0 {
					return
				}
				meta := p.row(itemAddress)
				meta["proxy_collections"] = []int{int(collectionField)}
				exchange = &Exchange{
					Source: "proxy", RequestAddr: requestAddress, ResponseAddr: responseAddress,
					RequestRaw: requestRaw, ResponseRaw: responseRaw, Meta: meta,
				}
				if len(requestRaw) > 0 && !requestStartRE.Match(requestRaw) {
					*warnings = append(*warnings, fmt.Sprintf("Proxy row %d request bytes do not start with an HTTP method", itemAddress))
					exchange = nil
					return
				}
				if len(responseRaw) > 0 && !bytes.HasPrefix(responseRaw, []byte("HTTP/")) {
					*warnings = append(*warnings, fmt.Sprintf("Proxy row %d response bytes do not start with HTTP/", itemAddress))
					exchange.ResponseRaw = nil
				}
			})
			if err != nil {
				*warnings = append(*warnings, fmt.Sprintf("Proxy row %d could not be decoded: %s", itemAddress, err))
				continue
			}
			if exchange != nil {
				out = append(out, exchange)
			}
		}
	}
	p.report("Proxy history extracted", 32)
	return out
}

func (p *BurpProject) extractRepeater(warnings *[]string) ([]*Exchange, RepeaterInfo) {
	p.report("Extracting Repeater tabs", 32)
	root := p.parseObject(p.Header.ProjectRoot, 16)
	repeaterAddress := p.readAddress(root, 2)
	if repeaterAddress == 0 {
		return []*Exchange{}, emptyRepeater()
	}
	repeater := p.parseObject(repeaterAddress, 16)
	tabCollection := p.readAddress(repeater, 1)
	groupCollection := p.readAddress(repeater, 4)

	groups := []Group{}
	if groupCollection != 0 {
		err := catchFormat(func() {
			for _, groupAddress := range p.directCollection(groupCollection) {
				if groupAddress == 0 {
					continue
				}
				group := p.parseObject(groupAddress, 16)
				groupInfo := Group{Address: groupAddress, Name: p.immutableString(p.readAddress(group, 0))}
				if color := p.readU8(group, 1); color != nil {
					groupInfo.Color = intPtr(int(*color))
				}
				if expanded := p.readU8(group, 2); expanded != nil {
					groupInfo.Expanded = boolPtr(*expanded != 0)
				}
				groupInfo.Index = p.readI32(group, 3)
				groupInfo.UUID = p.uuidObject(p.readAddress(group, 4))
				groups = append(groups, groupInfo)
			}
		})
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("Repeater groups could not be decoded: %s", err))
		}
	}
	groupByAddress := map[int64]*Group{}
	for index := range groups {
		groupByAddress[groups[index].Address] = &groups[index]
	}

	tabsOut := []Tab{}
	out := []*Exchange{}
	if tabCollection != 0 {
		var tabAddresses []int64
		if err := catchFormat(func() { tabAddresses = p.directCollection(tabCollection) }); err != nil {
			*warnings = append(*warnings, fmt.Sprintf("Repeater tab collection could not be decoded: %s", err))
			tabAddresses = []int64{}
		}
		for tabIndex, tabAddress := range tabAddresses {
			if len(tabAddresses) > 0 {
				p.report("Extracting Repeater tabs", 34+8*float64(tabIndex+1)/float64(len(tabAddresses)))
			}
			if tabAddress == 0 {
				continue
			}
			var tabInfo Tab
			err := catchFormat(func() {
				tab := p.parseObject(tabAddress, 16)
				captionAddress := p.readAddress(tab, 0)
				var caption *string
				if captionAddress != 0 {
					caption = p.mutableString(captionAddress)
				}
				groupAddress := p.readAddress(tab, 32)
				tabInfo = Tab{
					Address: tabAddress,
					Caption: caption,
					UUID:    p.uuidObject(p.readAddress(tab, 33)),
					Group:   groupByAddress[groupAddress],
				}
				pairCollection := p.readAddress(tab, 2)
				pairAddresses := []int64{}
				if pairCollection != 0 {
					if err := catchFormat(func() { pairAddresses = p.directCollection(pairCollection) }); err != nil {
						if err2 := catchFormat(func() { pairAddresses = p.chunkedCollection(pairCollection) }); err2 != nil {
							*warnings = append(*warnings, fmt.Sprintf("Repeater pairs for tab %v could not be decoded: %s", caption, err2))
						}
					}
				}
				pairIndex := 0
				for _, pairAddress := range pairAddresses {
					if pairAddress == 0 {
						continue
					}
					pair := p.parseObject(pairAddress, 16)
					requestAddress := p.readAddress(pair, 2)
					responseAddress := p.readAddress(pair, 3)
					var requestRaw, responseRaw []byte
					if requestAddress != 0 {
						requestRaw = p.variableRecord(requestAddress)
					}
					if responseAddress != 0 {
						responseRaw = p.variableRecord(responseAddress)
					}
					if len(requestRaw) == 0 && len(responseRaw) == 0 {
						continue
					}
					pairIndex++
					out = append(out, &Exchange{
						Source: "repeater", RequestAddr: requestAddress, ResponseAddr: responseAddress,
						RequestRaw: requestRaw, ResponseRaw: responseRaw,
						Meta: map[string]any{
							"tab": caption, "tab_uuid": tabInfo.UUID,
							"group": tabInfo.Group, "pair_index": pairIndex,
						},
					})
				}
				tabInfo.PairCount = pairIndex
				tabsOut = append(tabsOut, tabInfo)
			})
			if err != nil {
				*warnings = append(*warnings, fmt.Sprintf("Repeater tab %d could not be decoded: %s", tabAddress, err))
			}
		}
	}
	p.report("Repeater tabs extracted", 42)
	return out, RepeaterInfo{Tabs: tabsOut, Groups: groups}
}

func (p *BurpProject) extractSiteMap(warnings *[]string) []*Exchange {
	p.report("Extracting Site Map", 42)
	root := p.parseObject(p.Header.ProjectRoot, 16)
	targetAddress := p.readAddress(root, 3)
	if targetAddress == 0 {
		return []*Exchange{}
	}
	target := p.parseObject(targetAddress, 16)
	indexAddress := p.readAddress(target, 3)
	if indexAddress == 0 {
		return []*Exchange{}
	}
	index := p.parseObject(indexAddress, 16)
	expectedSize := p.readI32(index, 2)
	bucketCollection := p.readAddress(index, 3)
	if expectedSize == nil || bucketCollection == 0 {
		return []*Exchange{}
	}
	var buckets []int64
	if err := catchFormat(func() { buckets = p.chunkedCollection(bucketCollection) }); err != nil {
		*warnings = append(*warnings, fmt.Sprintf("Target identity index could not be decoded: %s", err))
		return []*Exchange{}
	}
	out := []*Exchange{}
	seenMessages := map[int64]bool{}
	decodedEntries := 0
	for bucketIndex, bucketAddress := range buckets {
		if len(buckets) > 0 {
			p.report("Extracting Site Map", 42+14*float64(bucketIndex+1)/float64(len(buckets)))
		}
		if bucketAddress == 0 {
			continue
		}
		err := catchFormat(func() {
			bucket := p.parseObject(bucketAddress, 16)
			bucketSize := p.readI32(bucket, 0)
			tupleAddress := p.readAddress(bucket, 1)
			if bucketSize == nil || tupleAddress == 0 {
				return
			}
			count, payload := p.variableArray(tupleAddress, 24)
			if *bucketSize > count {
				return
			}
			for indexEntry := 0; indexEntry < *bucketSize; indexEntry++ {
				offset := indexEntry * 24
				keyAddress := int64(binary.BigEndian.Uint64(payload[offset+8:]))
				if keyAddress <= 0 {
					continue
				}
				decodedEntries++
				node := p.parseObject(keyAddress, 16)
				messageAddress := p.readAddress(node, 33)
				if messageAddress == 0 || seenMessages[messageAddress] {
					continue
				}
				seenMessages[messageAddress] = true
				message := p.parseObject(messageAddress, 16)
				requestAddress := p.readAddress(message, 0)
				responseAddress := p.readAddress(message, 1)
				var requestRaw, responseRaw []byte
				if requestAddress != 0 {
					requestRaw = p.variableRecord(requestAddress)
				}
				if responseAddress != 0 {
					responseRaw = p.variableRecord(responseAddress)
				}
				if len(requestRaw) == 0 && len(responseRaw) == 0 {
					continue
				}
				if len(requestRaw) > 0 && !requestStartRE.Match(requestRaw) {
					continue
				}
				if len(responseRaw) > 0 && !bytes.HasPrefix(responseRaw, []byte("HTTP/")) {
					responseRaw = nil
				}
				out = append(out, &Exchange{
					Source: "site-map", RequestAddr: requestAddress, ResponseAddr: responseAddress,
					RequestRaw: requestRaw, ResponseRaw: responseRaw,
					Meta: map[string]any{
						"node_type": node.Type, "node_subtype": node.Subtype,
						"node_address": keyAddress, "message_address": messageAddress,
						"time_epoch_ms": p.readI64(message, 3),
					},
				})
			}
		})
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("Target bucket %d could not be decoded: %s", bucketAddress, err))
		}
	}
	if *expectedSize != 0 && decodedEntries != *expectedSize {
		*warnings = append(*warnings, fmt.Sprintf("Target index reported %d entries; decoded %d", *expectedSize, decodedEntries))
	}
	p.report("Site Map extracted", 56)
	return out
}

type Frame struct {
	Address int64
	Kind    string
	Payload []byte
}

func (p *BurpProject) scanFrames() []Frame {
	type mark struct {
		offset int
		kind   string
	}
	p.report("Scanning HTTP frames", 56)
	marks := []mark{}
	for _, match := range requestSearchRE.FindAllIndex(p.Data, -1) {
		marks = append(marks, mark{offset: match[0], kind: "request"})
	}
	p.report("Scanning HTTP frames", 60)
	for _, match := range responseSearchRE.FindAllIndex(p.Data, -1) {
		marks = append(marks, mark{offset: match[0], kind: "response"})
	}
	p.report("Scanning HTTP frames", 64)
	sort.SliceStable(marks, func(i, j int) bool { return marks[i].offset < marks[j].offset })
	frames := []Frame{}
	seen := map[int64]bool{}
	for markIndex, current := range marks {
		if len(marks) > 0 && markIndex%(1<<14) == 0 {
			p.report("Scanning HTTP frames", 64+6*float64(markIndex)/float64(len(marks)))
		}
		record := int64(current.offset) - 8
		if record < burpHeaderSize || seen[record] {
			continue
		}
		if record+8 > int64(len(p.Data)) {
			continue
		}
		total := p.i32(record)
		logical := p.i32(record + 4)
		if logical <= 0 || int64(total) != 8+int64(logical) || int64(current.offset)+int64(logical) > int64(len(p.Data)) {
			continue
		}
		payload := p.Data[current.offset : int64(current.offset)+int64(logical)]
		if current.kind == "request" && !requestStartRE.Match(payload) {
			continue
		}
		if current.kind == "response" && !bytes.HasPrefix(payload, []byte("HTTP/")) {
			continue
		}
		seen[record] = true
		frames = append(frames, Frame{Address: record, Kind: current.kind, Payload: payload})
	}
	p.report("HTTP frames scanned", 70)
	return frames
}

func (p *BurpProject) collaborator(frames []Frame, warnings *[]string) Collaborator {
	p.report("Collaborator recovery", 70)
	domains := map[string]bool{}
	for _, match := range collaboratorRE.FindAllString(string(p.Data), -1) {
		domains[strings.ToLower(match)] = true
	}
	p.report("Collaborator recovery", 72)
	requests := []Frame{}
	responses := []Frame{}
	for _, frame := range frames {
		if frame.Kind == "request" && collaboratorRE.Match(frame.Payload) {
			requests = append(requests, frame)
		} else if frame.Kind == "response" {
			limit := minInt(4096, len(frame.Payload))
			if bytes.Contains(frame.Payload[:limit], []byte("Burp Collaborator")) {
				responses = append(responses, frame)
			}
		}
	}
	for _, frame := range append(append([]Frame{}, requests...), responses...) {
		for _, match := range collaboratorRE.FindAllString(string(frame.Payload), -1) {
			domains[strings.ToLower(match)] = true
		}
	}
	p.report("Collaborator recovery", 74)
	interactions := []Interaction{}
	usedResponses := map[int64]bool{}
	for requestIndex, request := range requests {
		if len(requests) > 0 {
			p.report("Collaborator recovery", 74+8*float64(requestIndex+1)/float64(len(requests)))
		}
		var response *Frame
		bestDistance := int64(0)
		for index := range responses {
			candidate := &responses[index]
			if usedResponses[candidate.Address] {
				continue
			}
			distance := candidate.Address - request.Address
			if distance < 0 {
				distance = -distance
			}
			if response == nil || distance < bestDistance {
				response = candidate
				bestDistance = distance
			}
		}
		if response != nil {
			usedResponses[response.Address] = true
		}
		parsedRequest, ok := parseHTTP(request.Payload, true, 50_000, intPtr(len(request.Payload)))
		if !ok || parsedRequest.Request == nil {
			continue
		}
		var parsedResponse *ResponseMessage
		if response != nil {
			if parsed, ok := parseHTTP(response.Payload, false, 50_000, intPtr(len(response.Payload))); ok {
				parsedResponse = parsed.Response
			}
		}
		enrichRequest(parsedRequest.Request, "")
		host := parsedRequest.Request.HostHeader
		interaction := Interaction{
			Type: "HTTP", Host: host, Method: parsedRequest.Request.Method,
			Path: parsedRequest.Request.Path, RequestLine: parsedRequest.Request.RequestLine,
			RequestAddress: request.Address, Request: parsedRequest.Request,
			Response: parsedResponse,
		}
		if parsedResponse != nil {
			interaction.ResponseStatus = intPtr(parsedResponse.Status)
			if server := headerValue(parsedResponse.Headers, "server"); server != "" {
				interaction.ResponseServer = &server
			}
		}
		if response != nil {
			interaction.ResponseAddress = int64Ptr(response.Address)
		}
		interactions = append(interactions, interaction)
	}
	if len(requests) > 0 && len(responses) == 0 {
		*warnings = append(*warnings, "Collaborator requests were found but no HTTP interaction responses were recovered")
	}
	domainList := make([]string, 0, len(domains))
	for domain := range domains {
		domainList = append(domainList, domain)
	}
	sort.Strings(domainList)
	types := []string{}
	if len(interactions) > 0 {
		types = append(types, "HTTP")
	}
	p.report("Collaborator recovered", 82)
	return Collaborator{
		DomainsSeen: domainList, InteractionTypesSeen: types, Interactions: interactions,
		Note: "HTTP interactions are recovered from framed request/response records. " +
			"DNS/SMTP interaction logs are not stored as ordinary HTTP frames and are " +
			"not recovered by this parser.",
	}
}

func (p *BurpProject) extract(maxBody int, warnings *[]string) *ExtractionResult {
	proxy := p.extractProxy(warnings)
	repeater, repeaterInfo := p.extractRepeater(warnings)
	siteMap := p.extractSiteMap(warnings)
	all := make([]*Exchange, 0, len(proxy)+len(repeater)+len(siteMap))
	all = append(all, proxy...)
	all = append(all, repeater...)
	all = append(all, siteMap...)

	frames := p.scanFrames()
	byAddress := map[int64]Frame{}
	for _, frame := range frames {
		byAddress[frame.Address] = frame
	}
	knownAddresses := map[int64]bool{}
	for _, exchange := range all {
		if exchange.RequestAddr != 0 {
			knownAddresses[exchange.RequestAddr] = true
		}
		if exchange.ResponseAddr != 0 {
			knownAddresses[exchange.ResponseAddr] = true
		}
	}

	collaborator := p.collaborator(frames, warnings)
	p.report("Frame attribution", 84)
	for _, interaction := range collaborator.Interactions {
		knownAddresses[interaction.RequestAddress] = true
		if interaction.ResponseAddress != nil {
			knownAddresses[*interaction.ResponseAddress] = true
		}
	}
	unattributed := []Frame{}
	for _, frame := range frames {
		if !knownAddresses[frame.Address] {
			unattributed = append(unattributed, frame)
		}
	}
	if len(unattributed) > 0 {
		first := make([]string, 0, minInt(8, len(unattributed)))
		for index := 0; index < len(unattributed) && index < 8; index++ {
			first = append(first, fmt.Sprintf("%d", unattributed[index].Address))
		}
		*warnings = append(*warnings, fmt.Sprintf(
			"%d framed HTTP record(s) were not linked to Proxy, Repeater, Site Map or "+
				"Collaborator metadata (first addresses: %s)",
			len(unattributed), strings.Join(first, ", ")))
	}
	for _, exchange := range all {
		if exchange.RequestAddr != 0 {
			if _, ok := byAddress[exchange.RequestAddr]; !ok {
				*warnings = append(*warnings, fmt.Sprintf("request frame at %d was referenced but did not validate", exchange.RequestAddr))
			}
		}
		if exchange.ResponseAddr != 0 {
			if _, ok := byAddress[exchange.ResponseAddr]; !ok {
				*warnings = append(*warnings, fmt.Sprintf("response frame at %d was referenced but did not validate", exchange.ResponseAddr))
			}
		}
	}

	var projectName *string
	func() {
		defer func() {
			if recover() != nil {
				// project name is optional
			}
		}()
		root := p.parseObject(p.Header.ProjectRoot, 16)
		projectName = p.immutableString(p.readAddress(root, 6))
	}()

	coverage := map[string]any{
		"proxy_items":                    len(proxy),
		"repeater_pairs":                 len(repeater),
		"site_map_messages":              len(siteMap),
		"framed_http_records":            len(frames),
		"unattributed_frames":            len(unattributed),
		"collaborator_http_interactions": len(collaborator.Interactions),
	}
	p.report("Burp extraction complete", 88)
	return &ExtractionResult{
		Items: all, Collaborator: collaborator, Repeater: repeaterInfo,
		Coverage: coverage, ProjectName: projectName, Header: &p.Header,
	}
}
