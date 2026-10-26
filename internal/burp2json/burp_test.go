package burp2json

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

type heapField struct {
	id    byte
	kind  byte // a=address/i64, i=i32, s=i16, b=u8
	value int64
}

func addrField(id byte, value int64) heapField { return heapField{id: id, kind: 'a', value: value} }
func i64Field(id byte, value int64) heapField  { return heapField{id: id, kind: 'a', value: value} }
func i32Field(id byte, value int) heapField    { return heapField{id: id, kind: 'i', value: int64(value)} }
func i16Field(id byte, value int) heapField    { return heapField{id: id, kind: 's', value: int64(value)} }
func u8Field(id byte, value int) heapField     { return heapField{id: id, kind: 'b', value: int64(value)} }

type heapWriter struct {
	body []byte
	base int64
}

func newHeapWriter() *heapWriter { return &heapWriter{base: 72} }

func (h *heapWriter) add(data []byte) int64 {
	address := h.base + int64(len(h.body))
	h.body = append(h.body, data...)
	return address
}

func (h *heapWriter) record(payload []byte) int64 {
	logical := len(payload)
	total := 8 + maxInt(logical, 1)
	buffer := make([]byte, 8, 8+maxInt(logical, 1))
	binary.BigEndian.PutUint32(buffer[0:], uint32(total))
	binary.BigEndian.PutUint32(buffer[4:], uint32(logical))
	buffer = append(buffer, payload...)
	if logical == 0 {
		buffer = append(buffer, 0)
	}
	return h.add(buffer)
}

func (h *heapWriter) array(payload []byte, elementSize int) int64 {
	count := len(payload) / elementSize
	total := 8 + maxInt(len(payload), 1)
	buffer := make([]byte, 8, total)
	binary.BigEndian.PutUint32(buffer[0:], uint32(total))
	binary.BigEndian.PutUint32(buffer[4:], uint32(count))
	buffer = append(buffer, payload...)
	if len(payload) == 0 {
		buffer = append(buffer, 0)
	}
	return h.add(buffer)
}

func (h *heapWriter) text(value string) int64 {
	units := utf16.Encode([]rune(value))
	payload := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.BigEndian.PutUint16(payload[index*2:], unit)
	}
	return h.array(payload, 2)
}

func (h *heapWriter) immutableString(value string) int64 {
	return h.obj([]heapField{addrField(0, h.text(value))}, 0, 0)
}

func (h *heapWriter) obj(fields []heapField, typeID, subtype byte) int64 {
	sorted := append([]heapField{}, fields...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].id < sorted[i].id {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	sizes := map[byte]int{'a': 8, 'i': 4, 's': 2, 'b': 1}
	headerSize := 4 + len(sorted)*3
	table := make([]byte, headerSize)
	table[0], table[1], table[2], table[3] = 0, typeID, subtype, byte(len(sorted))
	values := []byte{}
	rel := headerSize
	for index, field := range sorted {
		table[4+index*3] = field.id
		binary.BigEndian.PutUint16(table[4+index*3+1:], uint16(rel))
		switch field.kind {
		case 'a':
			var encoded [8]byte
			binary.BigEndian.PutUint64(encoded[:], uint64(field.value))
			values = append(values, encoded[:]...)
		case 'i':
			var encoded [4]byte
			binary.BigEndian.PutUint32(encoded[:], uint32(int32(field.value)))
			values = append(values, encoded[:]...)
		case 's':
			var encoded [2]byte
			binary.BigEndian.PutUint16(encoded[:], uint16(int16(field.value)))
			values = append(values, encoded[:]...)
		case 'b':
			values = append(values, byte(field.value))
		}
		rel += sizes[field.kind]
	}
	return h.add(append(table, values...))
}

func (h *heapWriter) chunkedCollection(items []int64) int64 {
	slots := make([]byte, len(items)*8)
	for index, item := range items {
		binary.BigEndian.PutUint64(slots[index*8:], uint64(item))
	}
	chunk := h.array(slots, 8)
	chunkListBacking := h.array(func() []byte {
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], uint64(chunk))
		return raw[:]
	}(), 8)
	chunkList := h.obj([]heapField{i32Field(0, 1), addrField(1, chunkListBacking)}, 0, 0)
	return h.obj([]heapField{
		i32Field(0, len(items)),
		i32Field(1, maxInt(1, len(items))),
		addrField(2, chunkList),
		i32Field(3, 0),
	}, 0, 0)
}

func (h *heapWriter) directCollection(items []int64) int64 {
	slots := make([]byte, len(items)*8)
	for index, item := range items {
		binary.BigEndian.PutUint64(slots[index*8:], uint64(item))
	}
	backing := h.array(slots, 8)
	return h.obj([]heapField{i32Field(0, len(items)), addrField(1, backing)}, 0, 0)
}

func (h *heapWriter) finish(projectRoot int64) []byte {
	header := make([]byte, 72)
	binary.BigEndian.PutUint32(header[0:], burpMagic)
	binary.BigEndian.PutUint32(header[4:], 1)
	binary.BigEndian.PutUint32(header[8:], 0x80527974)
	binary.BigEndian.PutUint16(header[12:], 217)
	binary.BigEndian.PutUint16(header[14:], 217)
	binary.BigEndian.PutUint32(header[16:], 0x12345678)
	binary.BigEndian.PutUint64(header[40:], 0)
	binary.BigEndian.PutUint64(header[48:], 0x7FFFFFFFFFFFFFFF)
	binary.BigEndian.PutUint64(header[56:], uint64(h.base+int64(len(h.body))))
	binary.BigEndian.PutUint64(header[64:], uint64(projectRoot))
	return append(header, h.body...)
}

func buildTestProject(t *testing.T) (string, map[string]int64) {
	t.Helper()
	heap := newHeapWriter()
	request := heap.record([]byte("GET /api/items?x=1 HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Cookie: sid=super-secret\r\n" +
		"X-Dup: first\r\n" +
		"X-Dup: second\r\n" +
		"Authorization: Bearer top-secret-token\r\n" +
		"\r\n"))
	response := heap.record([]byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 17\r\n" +
		"\r\n" +
		`{"ok":true,"n":1}`))
	uniqueRequest := heap.record([]byte("POST /api/login HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 31\r\n" +
		"\r\n" +
		`{"username":"a","password":"b"}`))
	uniqueResponse := heap.record([]byte("HTTP/1.1 302 Found\r\n" +
		"Location: /home\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"))
	repeaterRequest := heap.record([]byte("GET /repeater-only HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	repeaterResponse := heap.record([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	collaboratorRequest := heap.record([]byte("GET /probe HTTP/1.1\r\nHost: abcdefghijklmnop.oastify.com\r\nAccept: */*\r\n\r\n"))
	collaboratorResponse := heap.record([]byte("HTTP/1.1 200 OK\r\nServer: Burp Collaborator https://burpcollaborator.net/\r\nContent-Length: 2\r\n\r\nOK"))

	hostWrapper := heap.obj([]heapField{addrField(0, heap.text("example.test"))}, 0, 0)
	service := heap.obj([]heapField{
		addrField(0, hostWrapper),
		i32Field(1, 443),
		u8Field(2, 1),
	}, 0, 0)
	metadata := heap.obj([]heapField{addrField(0, service)}, 0, 0)
	comment := heap.obj([]heapField{addrField(0, heap.text("test note"))}, 0, 0)

	proxyRow := heap.obj([]heapField{
		i32Field(0, 42),
		addrField(1, heap.immutableString("GET")),
		addrField(2, metadata),
		addrField(3, comment),
		addrField(4, heap.immutableString("203.0.113.7")),
		i16Field(6, 200),
		i16Field(7, 0x0104),
		i32Field(8, 17),
		addrField(9, heap.immutableString("Test title")),
		addrField(10, heap.immutableString("sid=super-secret")),
		i64Field(11, 1700000000000),
		u8Field(13, 3),
		i32Field(14, 8080),
		addrField(15, request),
		addrField(18, response),
	}, 1, 0)
	proxy := heap.obj([]heapField{addrField(0, heap.chunkedCollection([]int64{proxyRow}))}, 0, 0)

	repeaterPair := heap.obj([]heapField{addrField(2, repeaterRequest), addrField(3, repeaterResponse)}, 0, 0)
	repeaterTab := heap.obj([]heapField{
		addrField(0, heap.immutableString("1")),
		addrField(2, heap.directCollection([]int64{repeaterPair})),
	}, 0, 0)
	repeater := heap.obj([]heapField{addrField(1, heap.directCollection([]int64{repeaterTab}))}, 0, 0)

	duplicateMessage := heap.obj([]heapField{
		addrField(0, request), addrField(1, response), i64Field(3, 1700000001000),
	}, 0, 0)
	uniqueMessage := heap.obj([]heapField{
		addrField(0, uniqueRequest), addrField(1, uniqueResponse), i64Field(3, 1700000002000),
	}, 0, 0)
	duplicateNode := heap.obj([]heapField{addrField(33, duplicateMessage)}, 3, 0)
	uniqueNode := heap.obj([]heapField{addrField(33, uniqueMessage)}, 3, 0)
	tuples := make([]byte, 48)
	binary.BigEndian.PutUint64(tuples[8:], uint64(duplicateNode))
	binary.BigEndian.PutUint64(tuples[32:], uint64(uniqueNode))
	tupleArray := heap.array(tuples, 24)
	bucket := heap.obj([]heapField{i32Field(0, 2), addrField(1, tupleArray)}, 0, 0)
	buckets := heap.chunkedCollection([]int64{bucket})
	index := heap.obj([]heapField{i32Field(2, 2), addrField(3, buckets)}, 0, 0)
	target := heap.obj([]heapField{addrField(3, index)}, 0, 0)

	projectName := heap.immutableString("unit-test-project")
	root := heap.obj([]heapField{
		addrField(1, proxy),
		addrField(2, repeater),
		addrField(3, target),
		addrField(6, projectName),
	}, 0, 6)

	path := filepath.Join(t.TempDir(), "fixture.burp")
	if err := os.WriteFile(path, heap.finish(root), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, map[string]int64{
		"request": request, "response": response,
		"collaborator_request": collaboratorRequest, "collaborator_response": collaboratorResponse,
	}
}

func readTestItems(t *testing.T, path string) ([]Item, *ExtractionResult, []string, string) {
	t.Helper()
	warnings := []string{}
	raw, method, extra := readBurp(path, 200_000, &warnings)
	items := finalizeItems(mergeExchanges(raw), 200_000)
	return items, extra, warnings, method
}

func findSource(items []Item, source string) *Item {
	for index := range items {
		if items[index].SourceTool == source {
			return &items[index]
		}
	}
	return nil
}

func TestHeapHeaderAndExtraction(t *testing.T) {
	path, _ := buildTestProject(t)
	items, extra, warnings, method := readTestItems(t, path)
	if method != "burp-heap" {
		t.Fatalf("method = %q, want burp-heap", method)
	}
	if extra.Header == nil || extra.Header.SchemaCurrent != 217 {
		t.Fatalf("schema = %+v, want 217", extra.Header)
	}
	if extra.ProjectName == nil || *extra.ProjectName != "unit-test-project" {
		t.Fatalf("project name = %v", extra.ProjectName)
	}
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3", len(items))
	}

	proxy := findSource(items, "proxy")
	if proxy == nil {
		t.Fatal("proxy item missing")
	}
	if proxy.Method == nil || *proxy.Method != "GET" || proxy.Path == nil || *proxy.Path != "/api/items" {
		t.Fatalf("proxy method/path = %v %v", proxy.Method, proxy.Path)
	}
	if proxy.Host == nil || *proxy.Host != "example.test" || proxy.Port == nil || *proxy.Port != 443 {
		t.Fatalf("proxy host/port = %v %v", proxy.Host, proxy.Port)
	}
	if proxy.Protocol == nil || *proxy.Protocol != "https" || proxy.Status == nil || *proxy.Status != 200 {
		t.Fatalf("proxy protocol/status = %v %v", proxy.Protocol, proxy.Status)
	}
	if proxy.Comment == nil || *proxy.Comment != "test note" {
		t.Fatalf("comment = %v", proxy.Comment)
	}
	if proxy.Highlight == nil || *proxy.Highlight != "yellow" {
		t.Fatalf("highlight = %v", proxy.Highlight)
	}
	if proxy.Time == nil || *proxy.Time != 1700000000000 {
		t.Fatalf("time = %v", proxy.Time)
	}
	if value := metaStringPtr(proxy.Metadata, "burp_mime"); value == nil || *value != "JSON" {
		t.Fatalf("burp_mime = %v", value)
	}
	if value := metaStringPtr(proxy.Metadata, "cookie_header"); value == nil || *value != "sid=super-secret" {
		t.Fatalf("cookie_header = %v", value)
	}
	if !reflect.DeepEqual(proxy.AlsoSeenIn, []string{"site-map"}) {
		t.Fatalf("also = %v", proxy.AlsoSeenIn)
	}
	duplicates := [][2]string{}
	for _, header := range proxy.Request.Headers {
		if strings.EqualFold(header[0], "x-dup") {
			duplicates = append(duplicates, header)
		}
	}
	if !reflect.DeepEqual(duplicates, [][2]string{{"X-Dup", "first"}, {"X-Dup", "second"}}) {
		t.Fatalf("duplicate headers = %v", duplicates)
	}

	repeater := findSource(items, "repeater")
	if repeater == nil || repeater.Request == nil || repeater.Request.Method != "GET" {
		t.Fatalf("repeater = %+v", repeater)
	}
	if value := metaStringPtr(repeater.Metadata, "tab"); value == nil || *value != "1" {
		t.Fatalf("repeater tab = %v", value)
	}

	siteMap := findSource(items, "site-map")
	if siteMap == nil || siteMap.Method == nil || *siteMap.Method != "POST" {
		t.Fatalf("site map = %+v", siteMap)
	}
	if siteMap.Status == nil || *siteMap.Status != 302 {
		t.Fatalf("site map status = %v", siteMap.Status)
	}
	if siteMap.Time == nil || *siteMap.Time != 1700000002000 {
		t.Fatalf("site map time = %v", siteMap.Time)
	}
	expectedBody := [][2]any{{"username", "a"}, {"password", "b"}}
	if !reflect.DeepEqual(siteMap.Request.BodyParams, expectedBody) {
		t.Fatalf("body params = %#v", siteMap.Request.BodyParams)
	}

	if extra.Coverage["proxy_items"] != 1 || extra.Coverage["repeater_pairs"] != 1 ||
		extra.Coverage["site_map_messages"] != 2 ||
		extra.Coverage["collaborator_http_interactions"] != 1 || extra.Coverage["unattributed_frames"] != 0 {
		t.Fatalf("coverage = %#v", extra.Coverage)
	}
	if !reflect.DeepEqual(extra.Collaborator.DomainsSeen, []string{"abcdefghijklmnop.oastify.com"}) {
		t.Fatalf("domains = %v", extra.Collaborator.DomainsSeen)
	}
	if len(extra.Collaborator.Interactions) != 1 {
		t.Fatalf("interactions = %d", len(extra.Collaborator.Interactions))
	}
	for _, warning := range warnings {
		if strings.Contains(warning, "unattributed") {
			t.Fatalf("unexpected warning: %s", warning)
		}
	}
}

func TestRedaction(t *testing.T) {
	path, _ := buildTestProject(t)
	items, extra, _, _ := readTestItems(t, path)
	redactItems(items)
	redactCollaborator(&extra.Collaborator)
	encoded, _ := json.Marshal(items)
	text := string(encoded)
	if strings.Contains(text, "super-secret") || strings.Contains(text, "top-secret-token") {
		t.Fatalf("secret survived redaction: %s", text)
	}
	proxy := findSource(items, "proxy")
	if value := metaStringPtr(proxy.Metadata, "cookie_header"); value == nil || *value != "[REDACTED]" {
		t.Fatalf("cookie_header = %v", value)
	}
	if proxy.Request.Cookies["sid"] != "[REDACTED]" {
		t.Fatalf("cookies = %v", proxy.Request.Cookies)
	}
	headers := map[string]string{}
	for _, header := range proxy.Request.Headers {
		headers[strings.ToLower(header[0])] = header[1]
	}
	if headers["cookie"] != "[REDACTED]" || headers["authorization"] != "[REDACTED]" {
		t.Fatalf("headers = %v", headers)
	}
	siteMap := findSource(items, "site-map")
	bodyParams := map[string]any{}
	for _, pair := range siteMap.Request.BodyParams {
		bodyParams[pair[0].(string)] = pair[1]
	}
	if bodyParams["password"] != "[REDACTED]" {
		t.Fatalf("body params = %v", bodyParams)
	}
}

func TestCompactRedactionSidecar(t *testing.T) {
	path, _ := buildTestProject(t)
	out := filepath.Join(t.TempDir(), "redacted.json")
	if code := run([]string{
		path, "-o", out, "--redact", "--body-preview", "2", "--header-max", "4",
		"--no-progress",
	}); code != 0 {
		t.Fatalf("run returned %d", code)
	}
	mainData, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	recallData, err := os.ReadFile(recallOutputPath(out))
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{mainData, recallData} {
		if bytes.Contains(data, []byte("super-secret")) ||
			bytes.Contains(data, []byte("top-secret-token")) {
			t.Fatalf("secret survived redaction: %s", data)
		}
	}
	var recall compactRecall
	if err := json.Unmarshal(recallData, &recall); err != nil {
		t.Fatal(err)
	}
	if len(recall.Bodies) == 0 {
		t.Fatal("expected redacted bodies in the recall sidecar")
	}
}

func TestHostFilterAndChunking(t *testing.T) {
	path, _ := buildTestProject(t)
	out := filepath.Join(t.TempDir(), "all.json")
	if code := run([]string{path, "-o", out, "--host", "example", "--max-body", "10", "--no-progress"}); code != 0 {
		t.Fatalf("run returned %d", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var compact CompactDocument
	if err := json.Unmarshal(data, &compact); err != nil {
		t.Fatal(err)
	}
	if compact.Meta.Items != 3 || compact.Summary == nil || compact.Summary.Total != 3 {
		t.Fatalf("meta/summary = %d %#v", compact.Meta.Items, compact.Summary)
	}
	hostCount := 0
	for _, host := range compact.Summary.Hosts {
		if len(host) > 1 && host[0] == "example.test" {
			hostCount = int(host[1].(float64))
		}
	}
	if hostCount != 3 {
		t.Fatalf("example.test count = %d", hostCount)
	}
	truncated := false
	for _, item := range compact.Items {
		if request, ok := item[9].([]any); ok && request[6] != nil {
			truncated = true
		}
		if response, ok := item[10].([]any); ok && response[5] != nil {
			truncated = true
		}
	}
	if !truncated {
		t.Fatal("expected a truncated body")
	}

	chunkBase := filepath.Join(t.TempDir(), "chunked.json")
	if code := run([]string{path, "-o", chunkBase, "--chunk-items", "2", "--no-summary", "--no-progress"}); code != 0 {
		t.Fatalf("chunk run returned %d", code)
	}
	part1 := filepath.Join(filepath.Dir(chunkBase), "chunked_part001.json")
	part2 := filepath.Join(filepath.Dir(chunkBase), "chunked_part002.json")
	for _, partPath := range []string{part1, part2} {
		if _, err := os.Stat(partPath); err != nil {
			t.Fatalf("missing chunk %s: %v", partPath, err)
		}
	}
	partData, _ := os.ReadFile(part1)
	var part CompactDocument
	if err := json.Unmarshal(partData, &part); err != nil {
		t.Fatal(err)
	}
	if part.Summary != nil || len(part.Items) != 2 || part.Meta.Items != 2 {
		t.Fatalf("part summary/items/meta = %v %d %d", part.Summary, len(part.Items), part.Meta.Items)
	}
}

func TestCompactOutputAndRecall(t *testing.T) {
	path, _ := buildTestProject(t)
	out := filepath.Join(t.TempDir(), "compact.json")
	if code := run([]string{
		path, "-o", out, "--body-preview", "2", "--header-max", "4", "--no-progress",
	}); code != 0 {
		t.Fatalf("run returned %d", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var compact CompactDocument
	if err := json.Unmarshal(data, &compact); err != nil {
		t.Fatal(err)
	}
	if compact.Format != compactFormat || len(compact.Items) != 3 {
		t.Fatalf("format/items = %q %d", compact.Format, len(compact.Items))
	}
	if compact.Recall != "compact.recall.json" {
		t.Fatalf("recall = %q", compact.Recall)
	}
	if compact.Summary == nil || compact.Summary.Total != 3 {
		t.Fatalf("summary = %+v", compact.Summary)
	}
	if len(compact.Strings) == 0 || !strings.Contains(strings.Join(compact.Strings, "\n"), "…[") {
		t.Fatalf("expected a capped string, got %v", compact.Strings)
	}

	var proxy []any
	for _, item := range compact.Items {
		toolIndex := int(item[1].(float64))
		if compact.Strings[toolIndex] == "proxy" {
			proxy = item
			break
		}
	}
	if proxy == nil {
		t.Fatal("proxy item missing")
	}
	response := proxy[10].([]any)
	body := response[3].(string)
	if len(body) > 2 || !strings.Contains(body, "{") {
		t.Fatalf("body preview = %q", body)
	}
	if response[6] != "1p" {
		t.Fatalf("body ref = %v", response[6])
	}

	sidecar, err := os.ReadFile(recallOutputPath(out))
	if err != nil {
		t.Fatal(err)
	}
	var recall compactRecall
	if err := json.Unmarshal(sidecar, &recall); err != nil {
		t.Fatal(err)
	}
	if recall.Bodies["1p"] != `{"ok":true,"n":1}` {
		t.Fatalf("recall body = %q", recall.Bodies["1p"])
	}
	foundSecret := false
	for _, value := range recall.Strings {
		if value == "sid=super-secret" {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Fatalf("full header value missing from recall: %v", recall.Strings)
	}
}

func TestCompactFullDisablesRecall(t *testing.T) {
	path, _ := buildTestProject(t)
	out := filepath.Join(t.TempDir(), "full.json")
	if code := run([]string{
		path, "-o", out, "--body-preview", "2", "--header-max", "4", "--no-progress",
	}); code != 0 {
		t.Fatalf("preview run returned %d", code)
	}
	if _, err := os.Stat(recallOutputPath(out)); err != nil {
		t.Fatalf("expected a recall sidecar before --full: %v", err)
	}
	if code := run([]string{
		path, "-o", out, "--body-preview", "2", "--header-max", "4", "--full", "--no-progress",
	}); code != 0 {
		t.Fatalf("run returned %d", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var compact CompactDocument
	if err := json.Unmarshal(data, &compact); err != nil {
		t.Fatal(err)
	}
	if compact.Recall != "" {
		t.Fatalf("recall = %q", compact.Recall)
	}
	if _, err := os.Stat(recallOutputPath(out)); !os.IsNotExist(err) {
		t.Fatalf("recall sidecar should not exist: %v", err)
	}
	proxyBody := ""
	for _, item := range compact.Items {
		toolIndex := int(item[1].(float64))
		if compact.Strings[toolIndex] != "proxy" {
			continue
		}
		proxyBody = item[10].([]any)[3].(string)
	}
	if proxyBody != `{"ok":true,"n":1}` {
		t.Fatalf("full body = %q", proxyBody)
	}
}

func TestCompactDefault(t *testing.T) {
	path, _ := buildTestProject(t)
	out := filepath.Join(t.TempDir(), "default.json")
	if code := run([]string{path, "-o", out, "--no-progress"}); code != 0 {
		t.Fatalf("run returned %d", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var compact CompactDocument
	if err := json.Unmarshal(data, &compact); err != nil {
		t.Fatal(err)
	}
	if compact.Format != compactFormat || len(compact.Items) != 3 || compact.Recall != "" {
		t.Fatalf("format/items/recall = %q %d %q", compact.Format, len(compact.Items), compact.Recall)
	}
	if compact.Summary == nil || compact.Summary.Total != 3 {
		t.Fatalf("summary = %+v", compact.Summary)
	}
}

func TestCompactChunking(t *testing.T) {
	path, _ := buildTestProject(t)
	out := filepath.Join(t.TempDir(), "chunked.json")
	if code := run([]string{
		path, "-o", out, "--chunk-items", "2", "--body-preview", "2", "--header-max", "4",
		"--no-progress",
	}); code != 0 {
		t.Fatalf("run returned %d", code)
	}
	base := strings.TrimSuffix(out, ".json")
	for index, expected := range []int{2, 1} {
		partPath := fmt.Sprintf("%s_part%03d.json", base, index+1)
		data, err := os.ReadFile(partPath)
		if err != nil {
			t.Fatal(err)
		}
		var part CompactDocument
		if err := json.Unmarshal(data, &part); err != nil {
			t.Fatal(err)
		}
		if len(part.Items) != expected || part.Meta.Items != expected ||
			part.Meta.Part != index+1 || part.Meta.Parts != 2 {
			t.Fatalf("part %d meta/items = %+v/%d", index+1, part.Meta, len(part.Items))
		}
		if (part.Summary != nil) != (index == 0) {
			t.Fatalf("part %d summary = %+v", index+1, part.Summary)
		}
		if part.Recall == "" {
			t.Fatalf("part %d has no recall reference", index+1)
		}
		if _, err := os.Stat(recallOutputPath(partPath)); err != nil {
			t.Fatalf("part %d recall sidecar: %v", index+1, err)
		}
	}
}

func TestCompactBase64UsesRecall(t *testing.T) {
	result := &Result{
		Meta:         Meta{Tool: "burp2json", ItemCount: 1},
		Collaborator: emptyCollaborator(""),
		Repeater:     emptyRepeater(),
		Coverage:     map[string]any{},
		Items: []Item{{
			ID: 1, SourceTool: "proxy", Status: intPtr(200),
			Response: &ResponseMessage{
				Status: 200,
				BodyFields: BodyFields{
					Body: "AQID", BodyEncoding: "base64", BodyLength: 3,
				},
			},
		}},
	}
	compact, recall := buildCompactDocument(result, compactOptions{
		BodyPreview: 1024, HeaderMax: 512, RecallName: "base.recall.json",
	})
	if recall == nil || recall.Bodies["1p"] != "AQID" {
		t.Fatalf("recall = %#v", recall)
	}
	response := compact.Items[0][10].([]any)
	if response[3] != "" || response[4] != "base64" || response[5] != 3 || response[6] != "1p" {
		t.Fatalf("response = %#v", response)
	}

	full, fullRecall := buildCompactDocument(result, compactOptions{
		BodyPreview: 1024, HeaderMax: 512, KeepBase64: true,
	})
	if fullRecall != nil {
		t.Fatalf("unexpected recall: %#v", fullRecall)
	}
	if body := full.Items[0][10].([]any)[3]; body != "AQID" {
		t.Fatalf("full base64 body = %q", body)
	}
}

func TestInputIsNotModified(t *testing.T) {
	path, _ := buildTestProject(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	warnings := []string{}
	readBurp(path, 10_000, &warnings)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("input file changed")
	}
}

func TestHTTPChunkedAndCompressedBodies(t *testing.T) {
	decoded, complete := decodeChunked([]byte("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"))
	if !complete || string(decoded) != "Wikipedia" {
		t.Fatalf("chunked = %q complete=%v", decoded, complete)
	}
	var gzipBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBuffer)
	_, _ = gzipWriter.Write([]byte("hello"))
	_ = gzipWriter.Close()
	decoded, warning := decompressBody(gzipBuffer.Bytes(), "gzip")
	if warning != "" || string(decoded) != "hello" {
		t.Fatalf("gzip = %q warning=%q", decoded, warning)
	}
	var zlibBuffer bytes.Buffer
	zlibWriter := zlib.NewWriter(&zlibBuffer)
	_, _ = zlibWriter.Write([]byte("hello"))
	_ = zlibWriter.Close()
	decoded, warning = decompressBody(zlibBuffer.Bytes(), "deflate")
	if warning != "" || string(decoded) != "hello" {
		t.Fatalf("deflate = %q warning=%q", decoded, warning)
	}
}

func TestBodyEncoding(t *testing.T) {
	if fields := encodeBody([]byte("hello"), 100); fields.BodyEncoding != "utf-8" {
		t.Fatalf("encoding = %q", fields.BodyEncoding)
	}
	if fields := encodeBody([]byte{0, 1, 2}, 100); fields.BodyEncoding != "base64" {
		t.Fatalf("encoding = %q", fields.BodyEncoding)
	}
	truncated := encodeBody([]byte("abcdef"), 3)
	if truncated.Body != "abc" || !truncated.BodyTruncated || truncated.BodyLength != 6 {
		t.Fatalf("truncated = %+v", truncated)
	}
}

func TestParseHTTPDuplicateHeadersAndJSONParams(t *testing.T) {
	raw := []byte("POST /x?a=1&a=2 HTTP/1.1\r\nHost: h.test\r\n" +
		"Content-Type: application/json\r\nContent-Length: 20\r\n" +
		"X-A: 1\r\nX-A: 2\r\n\r\n{\"user\":\"bob\",\"n\":4}")
	parsed, ok := parseHTTP(raw, true, 1000, intPtr(len(raw)))
	if !ok || parsed.Consumed != len(raw) || len(parsed.Warnings) != 0 {
		t.Fatalf("parse = %+v ok=%v", parsed, ok)
	}
	enrichRequest(parsed.Request, "")
	if !reflect.DeepEqual(parsed.Request.QueryParams, [][2]any{{"a", "1"}, {"a", "2"}}) {
		t.Fatalf("query params = %#v", parsed.Request.QueryParams)
	}
	if !reflect.DeepEqual(parsed.Request.BodyParams, [][2]any{{"user", "bob"}, {"n", int64(4)}}) {
		t.Fatalf("body params = %#v", parsed.Request.BodyParams)
	}
}

func TestAbsoluteURLInference(t *testing.T) {
	request := &RequestMessage{Target: "https://example.test:8443/a?b=1"}
	url, host, port, scheme := inferURL(request, map[string]any{}, "", 0)
	if url != "https://example.test:8443/a?b=1" || host != "example.test" || port != 8443 || scheme != "https" {
		t.Fatalf("infer = %q %q %d %q", url, host, port, scheme)
	}
}

func TestXMLExport(t *testing.T) {
	request := base64.StdEncoding.EncodeToString([]byte("GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	response := base64.StdEncoding.EncodeToString([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	document := `<?xml version="1.0"?>
<items>
  <item>
    <time>2024-01-01T00:00:00Z</time>
    <url>https://example.test/a</url>
    <host ip="203.0.113.1">example.test</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/a</path>
    <request base64="true">` + request + `</request>
    <status>200</status>
    <response base64="true">` + response + `</response>
    <comment>review me</comment>
    <type>Proxy</type>
  </item>
</items>`
	path := filepath.Join(t.TempDir(), "export.xml")
	if err := os.WriteFile(path, []byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
	warnings := []string{}
	raw, method := readXML(path, 10_000, &warnings)
	items := finalizeItems(raw, 10_000)
	if method != "burp-xml" || len(items) != 1 {
		t.Fatalf("method/items = %q %d", method, len(items))
	}
	item := items[0]
	if item.SourceTool != "proxy" || item.Host == nil || *item.Host != "example.test" {
		t.Fatalf("item = %+v", item)
	}
	if item.Status == nil || *item.Status != 200 || item.Comment == nil || *item.Comment != "review me" {
		t.Fatalf("status/comment = %v %v", item.Status, item.Comment)
	}
	if item.Response == nil || item.Response.Body != "OK" {
		t.Fatalf("response = %+v", item.Response)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
}

func TestHAR(t *testing.T) {
	har := map[string]any{
		"log": map[string]any{"entries": []any{map[string]any{
			"startedDateTime": "2024-01-01T00:00:00Z",
			"request": map[string]any{
				"method": "POST", "url": "https://example.test:8443/api", "httpVersion": "HTTP/2",
				"headers":  []any{map[string]any{"name": "Content-Type", "value": "application/json"}},
				"postData": map[string]any{"mimeType": "application/json", "text": `{"a":1}`},
			},
			"response": map[string]any{
				"status": 201, "statusText": "Created", "httpVersion": "HTTP/2",
				"headers": []any{map[string]any{"name": "Content-Type", "value": "application/json"}},
				"content": map[string]any{"mimeType": "application/json", "text": `{"ok":true}`},
			},
		}}},
	}
	data, _ := json.Marshal(har)
	path := filepath.Join(t.TempDir(), "export.har")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	warnings := []string{}
	raw, method := readHAR(path, 10_000, &warnings)
	items := finalizeItems(raw, 10_000)
	if method != "har" || len(items) != 1 {
		t.Fatalf("method/items = %q %d", method, len(items))
	}
	item := items[0]
	if item.Host == nil || *item.Host != "example.test" || item.Port == nil || *item.Port != 8443 ||
		item.Protocol == nil || *item.Protocol != "https" {
		t.Fatalf("host/port/protocol = %v %v %v", item.Host, item.Port, item.Protocol)
	}
	if item.Status == nil || *item.Status != 201 {
		t.Fatalf("status = %v", item.Status)
	}
	if !reflect.DeepEqual(item.Request.BodyParams, [][2]any{{"a", int64(1)}}) {
		t.Fatalf("body params = %#v", item.Request.BodyParams)
	}
}

func TestFallbackCarverPairsMessages(t *testing.T) {
	raw := []byte("\x00garbage\x00" +
		"GET /fallback HTTP/1.1\r\nHost: fallback.test\r\n\r\n" +
		"HTTP/1.1 204 No Content\r\n\r\n" +
		"tail")
	path := filepath.Join(t.TempDir(), "unknown.bin")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	warnings := []string{}
	items, method, extra := readBurpFallback(path, 10_000, &warnings)
	if method != "frame-carver" || len(items) != 1 {
		t.Fatalf("method/items = %q %d", method, len(items))
	}
	if items[0].Request == nil || items[0].Request.Target != "/fallback" {
		t.Fatalf("request = %+v", items[0].Request)
	}
	if items[0].Response == nil || items[0].Response.Status != 204 {
		t.Fatalf("response = %+v", items[0].Response)
	}
	if len(extra.Collaborator.DomainsSeen) != 0 {
		t.Fatalf("domains = %v", extra.Collaborator.DomainsSeen)
	}
}

func TestSummary(t *testing.T) {
	raw := []byte("GET /b?z=1 HTTP/2\r\nHost: h.test\r\nAccept: */*\r\n\r\n")
	parsed, ok := parseHTTP(raw, true, 1000, intPtr(len(raw)))
	if !ok {
		t.Fatal("request parse failed")
	}
	enrichRequest(parsed.Request, "")
	responseParsed, ok := parseHTTP([]byte("HTTP/2 500 Oops\r\nContent-Type: text/html\r\n\r\nx"), false, 1000, intPtr(53))
	if !ok {
		t.Fatal("response parse failed")
	}
	item := Item{
		ID: 1, SourceTool: "proxy", Host: strPtr("h.test"), Port: intPtr(443),
		Protocol: strPtr("https"), URL: strPtr("https://h.test/b?z=1"),
		Highlight: strPtr("red"), Request: parsed.Request, Response: responseParsed.Response,
		Metadata: map[string]any{},
	}
	summary := buildSummary([]Item{item})
	if summary.TotalItems != 1 || summary.Hosts["h.test"] != 1 || summary.Methods["GET"] != 1 ||
		summary.StatusCodes["500"] != 1 || len(summary.ServerErrors) != 1 ||
		summary.ServerErrors[0].Status == nil || *summary.ServerErrors[0].Status != 500 ||
		summary.Highlights["red"] != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if len(summary.HostDetails) != 1 || summary.HostDetails[0].Count != 1 {
		t.Fatalf("host details = %+v", summary.HostDetails)
	}
}

func TestRealSample(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "real-sample.burp")
	if _, err := os.Stat(path); err != nil {
		t.Skip("testdata/real-sample.burp is not present")
	}
	warnings := []string{}
	raw, method, extra := readBurp(path, 200_000, &warnings)
	items := finalizeItems(mergeExchanges(raw), 200_000)
	if method != "burp-heap" || len(items) < 90 {
		t.Fatalf("method/items = %q %d", method, len(items))
	}
	for _, item := range items {
		if item.Protocol == nil || *item.Protocol != "https" || item.Host == nil || *item.Host != "chatgpt.com" {
			t.Fatalf("unexpected host/protocol: %v %v", item.Host, item.Protocol)
		}
	}
	hasJSComment := false
	for _, item := range items {
		if item.Comment != nil && *item.Comment == "js" {
			hasJSComment = true
		}
	}
	if !hasJSComment || len(extra.Collaborator.Interactions) < 1 || extra.Coverage["unattributed_frames"] != 242 {
		t.Fatalf("real sample coverage/comment = %#v", extra.Coverage)
	}
}
