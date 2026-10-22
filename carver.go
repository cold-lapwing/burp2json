package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type CarvedFrame struct {
	Offset   int64
	Kind     string
	Message  *parsedMessage
	Warnings []string
	Depth    int
}

type carvedMark struct {
	offset int
	kind   string
}

func carveBuffer(buf []byte, baseOffset int64, maxBody int, depth int) []CarvedFrame {
	marks := []carvedMark{}
	for _, match := range requestSearchRE.FindAllIndex(buf, -1) {
		marks = append(marks, carvedMark{offset: match[0], kind: "request"})
	}
	for _, match := range responseSearchRE.FindAllIndex(buf, -1) {
		marks = append(marks, carvedMark{offset: match[0], kind: "response"})
	}
	sort.SliceStable(marks, func(i, j int) bool { return marks[i].offset < marks[j].offset })

	found := []CarvedFrame{}
	for index, mark := range marks {
		limit := 0
		if index+1 < len(marks) {
			limit = marks[index+1].offset - mark.offset
		} else {
			limit = minInt(len(buf)-mark.offset, 8_000_000)
		}
		if limit <= 0 {
			continue
		}
		chunk := buf[mark.offset : mark.offset+limit]
		parsed, ok := parseHTTP(chunk, mark.kind == "request", maxBody, nil)
		if !ok {
			continue
		}
		found = append(found, CarvedFrame{
			Offset: baseOffset + int64(mark.offset), Kind: mark.kind,
			Message: parsed, Warnings: parsed.Warnings, Depth: depth,
		})
	}
	return found
}

type compressedStream struct {
	Offset int64
	Data   []byte
}

func findCompressedStreams(buf []byte, limit int) []compressedStream {
	out := []compressedStream{}
	n := len(buf)
	window := 8_000_000
	for i := 0; i+2 < n; i++ {
		b0, b1, b2 := buf[i], buf[i+1], buf[i+2]
		var decompressed []byte
		var err error
		end := i + window
		if end > n {
			end = n
		}
		if b0 == 0x78 && (b1 == 0x01 || b1 == 0x5E || b1 == 0x9C || b1 == 0xDA) &&
			((int(b0)<<8)|int(b1))%31 == 0 {
			reader, zerr := zlib.NewReader(bytes.NewReader(buf[i:end]))
			if zerr == nil {
				decompressed, err = io.ReadAll(io.LimitReader(reader, int64(limit)))
				reader.Close()
			} else {
				err = zerr
			}
		} else if b0 == 0x1F && b1 == 0x8B && b2 == 8 {
			reader, gerr := gzip.NewReader(bytes.NewReader(buf[i:end]))
			if gerr == nil {
				decompressed, err = io.ReadAll(io.LimitReader(reader, int64(limit)))
				reader.Close()
			} else {
				err = gerr
			}
		} else {
			continue
		}
		if err == nil && len(decompressed) >= 16 && bytes.Contains(decompressed, []byte("HTTP/")) {
			out = append(out, compressedStream{Offset: int64(i), Data: decompressed})
		}
	}
	return out
}

func pairCarved(found []CarvedFrame, source string) []*Exchange {
	sort.SliceStable(found, func(i, j int) bool { return found[i].Offset < found[j].Offset })
	items := []*Exchange{}
	var current *Exchange
	for _, frame := range found {
		if frame.Kind == "request" {
			current = &Exchange{
				Source: source, RequestAddr: frame.Offset,
				Request: frame.Message.Request, Warnings: append([]string{}, frame.Warnings...),
				Meta: map[string]any{},
			}
			items = append(items, current)
		} else {
			if current != nil && current.Response == nil {
				current.Response = frame.Message.Response
				current.ResponseAddr = frame.Offset
				current.Warnings = append(current.Warnings, frame.Warnings...)
			} else {
				items = append(items, &Exchange{
					Source: source, ResponseAddr: frame.Offset,
					Response: frame.Message.Response, Warnings: append([]string{}, frame.Warnings...),
					Meta: map[string]any{},
				})
			}
		}
	}
	return items
}

func readBurpFallback(path string, maxBody int, warnings *[]string) ([]*Exchange, string, *ExtractionResult) {
	data, err := os.ReadFile(path)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("could not read input: %s", err))
		return []*Exchange{}, "frame-carver", &ExtractionResult{
			Collaborator: emptyCollaborator("only payload domains are recoverable in fallback mode"),
			Repeater:     emptyRepeater(),
			Coverage:     map[string]any{},
		}
	}
	found := carveBuffer(data, 0, maxBody, 0)
	compressed := 0
	extraCollaborator := map[string]bool{}
	for _, stream := range findCompressedStreams(data, 64_000_000) {
		for _, match := range collaboratorRE.FindAllString(string(stream.Data), -1) {
			extraCollaborator[strings.ToLower(match)] = true
		}
		sub := carveBuffer(stream.Data, stream.Offset, maxBody, 1)
		if len(sub) > 0 {
			compressed++
			found = append(found, sub...)
		}
	}
	if compressed > 0 {
		*warnings = append(*warnings, fmt.Sprintf("recovered messages from %d compressed blob(s)", compressed))
	}
	items := pairCarved(found, "unknown")
	collaboratorSet := map[string]bool{}
	for _, match := range collaboratorRE.FindAllString(string(data), -1) {
		collaboratorSet[strings.ToLower(match)] = true
	}
	for domain := range extraCollaborator {
		collaboratorSet[domain] = true
	}
	domains := make([]string, 0, len(collaboratorSet))
	for domain := range collaboratorSet {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	if len(domains) > 0 {
		*warnings = append(*warnings, fmt.Sprintf("collaborator-style domains seen in file (%d)", len(domains)))
	}
	*warnings = append(*warnings, "fallback carver cannot recover tool names, tab names, comments, highlights, "+
		"Intruder configuration or Collaborator interaction logs")
	collaborator := emptyCollaborator("only payload domains are recoverable in fallback mode")
	collaborator.DomainsSeen = domains
	coverage := map[string]any{
		"proxy_items": 0, "repeater_pairs": 0, "site_map_messages": 0,
		"framed_http_records": len(found), "unattributed_frames": len(found),
		"collaborator_http_interactions": 0,
	}
	return items, "frame-carver", &ExtractionResult{
		Collaborator: collaborator, Repeater: emptyRepeater(), Coverage: coverage,
	}
}

func readBurp(path string, maxBody int, warnings *[]string) ([]*Exchange, string, *ExtractionResult) {
	project, err := NewBurpProject(path)
	if err == nil {
		var result *ExtractionResult
		err = catchFormat(func() {
			result = project.extract(maxBody, warnings)
		})
		if err == nil && result != nil && len(result.Items) > 0 {
			return result.Items, "burp-heap", result
		}
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("structural parser failed (%s); falling back to frame carver", err))
		} else {
			*warnings = append(*warnings, "structural parser found no HTTP items; falling back to frame carver")
		}
	} else {
		*warnings = append(*warnings, fmt.Sprintf("structural parser failed (%s); falling back to frame carver", err))
	}

	return readBurpFallback(path, maxBody, warnings)
}
