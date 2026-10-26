package burp2json

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
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

func carveBuffer(buf []byte, baseOffset int64, maxBody int, depth int,
	progress *progressBar, start, end float64) []CarvedFrame {
	progress.Update("Scanning request markers", start)
	marks := []carvedMark{}
	for _, match := range requestSearchRE.FindAllIndex(buf, -1) {
		marks = append(marks, carvedMark{offset: match[0], kind: "request"})
	}
	progress.Update("Response markers", start+(end-start)*0.2)
	for _, match := range responseSearchRE.FindAllIndex(buf, -1) {
		marks = append(marks, carvedMark{offset: match[0], kind: "response"})
	}
	sort.SliceStable(marks, func(i, j int) bool { return marks[i].offset < marks[j].offset })
	progress.Update("Carving HTTP frames", start+(end-start)*0.5)

	found := []CarvedFrame{}
	for index, mark := range marks {
		if len(marks) > 0 && (index == 0 || index%128 == 0) {
			progress.Update("Carving HTTP frames", start+(end-start)*0.5+
				(end-start)*0.5*float64(index)/float64(len(marks)))
		}
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
	progress.Update("Carved HTTP frames", end)
	return found
}

type compressedStream struct {
	Offset int64
	Data   []byte
}

func findCompressedStreams(buf []byte, limit int, progress *progressBar, start, end float64) []compressedStream {
	out := []compressedStream{}
	n := len(buf)
	window := 8_000_000
	progress.Update("Scanning compressed data", start)
	for i := 0; i+2 < n; i++ {
		if i%(1<<20) == 0 {
			progress.Update("Scanning compressed data", start+(end-start)*float64(i)/float64(n))
		}
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
	progress.Update("Compressed scan done", end)
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

func readBurpFallbackData(data []byte, maxBody int, warnings *[]string,
	progress *progressBar) ([]*Exchange, string, *ExtractionResult) {
	found := carveBuffer(data, 0, maxBody, 0, progress, 20, 42)
	compressed := 0
	extraCollaborator := map[string]bool{}
	streams := findCompressedStreams(data, 64_000_000, progress, 42, 62)
	for index, stream := range streams {
		for _, match := range collaboratorRE.FindAllString(string(stream.Data), -1) {
			extraCollaborator[strings.ToLower(match)] = true
		}
		start := 62.0
		end := 68.0
		if len(streams) > 0 {
			start += (end - start) * float64(index) / float64(len(streams))
			end = 62 + 6*float64(index+1)/float64(len(streams))
		}
		sub := carveBuffer(stream.Data, stream.Offset, maxBody, 1, progress, start, end)
		if len(sub) > 0 {
			compressed++
			found = append(found, sub...)
		}
	}
	if compressed > 0 {
		*warnings = append(*warnings, fmt.Sprintf("recovered messages from %d compressed blob(s)", compressed))
	}
	progress.Update("Pairing carved messages", 72)
	items := pairCarved(found, "unknown")
	progress.Update("Scanning domains", 78)
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
	progress.Update("Fallback complete", 88)
	return items, "frame-carver", &ExtractionResult{
		Collaborator: collaborator, Repeater: emptyRepeater(), Coverage: coverage,
	}
}

func readBurpFallback(path string, maxBody int, warnings *[]string) ([]*Exchange, string, *ExtractionResult) {
	data, err := readInputFile(path, nil)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("could not read input: %s", err))
		return []*Exchange{}, "frame-carver", &ExtractionResult{
			Collaborator: emptyCollaborator("only payload domains are recoverable in fallback mode"),
			Repeater:     emptyRepeater(),
			Coverage:     map[string]any{},
		}
	}
	return readBurpFallbackData(data, maxBody, warnings, nil)
}

func readBurpData(data []byte, maxBody int, warnings *[]string,
	progress *progressBar) ([]*Exchange, string, *ExtractionResult) {
	project, err := NewBurpProjectFromBytes(data)
	if err == nil {
		project.progress = progress
		progress.Update("Parsing Burp heap", 20)
		var result *ExtractionResult
		err = catchFormat(func() {
			result = project.extract(maxBody, warnings)
		})
		if err == nil && result != nil && len(result.Items) > 0 {
			progress.Update("Burp heap parsed", 90)
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

	progress.Update("Using frame carver", 20)
	return readBurpFallbackData(data, maxBody, warnings, progress)
}

func readBurp(path string, maxBody int, warnings *[]string) ([]*Exchange, string, *ExtractionResult) {
	data, err := readInputFile(path, nil)
	if err != nil {
		return readBurpFallback(path, maxBody, warnings)
	}
	return readBurpData(data, maxBody, warnings, nil)
}
