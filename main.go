package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const version = "2.0.0"

const aiInstructions = "This JSON was produced from a Burp Suite project by burp2json. 'summary' gives the " +
	"application overview (hosts, endpoints, parameters, cookies, status codes, tech). " +
	"'items' holds each HTTP request/response pair with ALL headers preserved " +
	"(headers are [name, value] lists to keep order and duplicates). Bodies are UTF-8 text " +
	"unless body_encoding is 'base64'. 'source_tool' is 'proxy', 'repeater', 'site-map' or " +
	"'unknown'; 'also_seen_in' lists other Burp tools that stored the same exchange. " +
	"'collaborator' contains payload domains and HTTP interactions recovered from the project. " +
	"Review for: access control, IDOR, auth/session handling, injection points, CORS, " +
	"security headers, information disclosure, and business-logic flaws. " +
	"Values marked [REDACTED] were removed by the user before sharing."

type cliOptions struct {
	input      string
	output     string
	format     string
	maxBody    int
	hosts      []string
	redact     bool
	chunkItems int
	noSummary  bool
	help       bool
}

func usage(w io.Writer) {
	fmt.Fprint(w, `burp2json - convert Burp Suite data to AI-friendly JSON

Usage:
  burp2json [options] INPUT

Input formats are auto-detected, or force one with --format:
  burp   Burp Suite project file (.burp)
  xml    Burp "Save items" XML export
  har    HAR file

Options:
  -o, --output PATH     output .json (default: <input>.json)
      --format FORMAT   burp, xml, or har
      --max-body BYTES  max bytes of each body to keep (default: 200000)
      --host TEXT       keep only items whose host contains TEXT (repeatable)
      --redact          redact auth headers, cookies, JWTs, secret-looking fields
      --chunk-items N   split into files of N items each
      --no-summary      omit the summary object
  -h, --help            show this help

Examples:
  burp2json project.burp
  burp2json --redact --chunk-items 50 project.burp -o review.json
  burp2json --host example.com proxy-export.xml

The input file is opened read-only and is never modified.
Use only on data from targets you are authorised to test.
`)
}

func parseArgs(argv []string) (cliOptions, error) {
	options := cliOptions{maxBody: 200_000}
	haveInput := false
	for index := 0; index < len(argv); index++ {
		arg := argv[index]
		if arg == "--" {
			for _, rest := range argv[index+1:] {
				if haveInput {
					return options, fmt.Errorf("unexpected extra argument %q", rest)
				}
				options.input = rest
				haveInput = true
			}
			break
		}
		if arg == "-h" || arg == "--help" {
			options.help = true
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			if haveInput {
				return options, fmt.Errorf("unexpected extra argument %q", arg)
			}
			options.input = arg
			haveInput = true
			continue
		}
		name := arg
		value := ""
		hasValue := false
		if equal := strings.IndexByte(arg, '='); equal >= 0 {
			name, value, hasValue = arg[:equal], arg[equal+1:], true
		}
		takeValue := func() (string, error) {
			if hasValue {
				return value, nil
			}
			index++
			if index >= len(argv) {
				return "", fmt.Errorf("option %s requires a value", name)
			}
			return argv[index], nil
		}
		switch name {
		case "-o", "--output":
			parsed, err := takeValue()
			if err != nil {
				return options, err
			}
			options.output = parsed
		case "--format":
			parsed, err := takeValue()
			if err != nil {
				return options, err
			}
			parsed = strings.ToLower(parsed)
			if parsed != "burp" && parsed != "xml" && parsed != "har" {
				return options, fmt.Errorf("--format must be burp, xml, or har")
			}
			options.format = parsed
		case "--max-body":
			parsed, err := takeValue()
			if err != nil {
				return options, err
			}
			number, err := strconv.Atoi(parsed)
			if err != nil {
				return options, fmt.Errorf("--max-body must be an integer")
			}
			options.maxBody = number
		case "--host":
			parsed, err := takeValue()
			if err != nil {
				return options, err
			}
			options.hosts = append(options.hosts, parsed)
		case "--redact":
			options.redact = true
		case "--chunk-items":
			parsed, err := takeValue()
			if err != nil {
				return options, err
			}
			number, err := strconv.Atoi(parsed)
			if err != nil {
				return options, fmt.Errorf("--chunk-items must be an integer")
			}
			options.chunkItems = number
		case "--no-summary":
			options.noSummary = true
		default:
			return options, fmt.Errorf("unknown option %q", arg)
		}
	}
	if options.help {
		return options, nil
	}
	if options.input == "" {
		return options, fmt.Errorf("input file is required")
	}
	if options.maxBody < 0 {
		return options, fmt.Errorf("--max-body must be >= 0")
	}
	if options.chunkItems < 0 {
		return options, fmt.Errorf("--chunk-items must be >= 0")
	}
	return options, nil
}

func detectFormat(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".burp":
		return "burp"
	case ".har":
		return "har"
	case ".xml":
		return "xml"
	}
	file, err := os.Open(path)
	if err != nil {
		return "burp"
	}
	defer file.Close()
	head := make([]byte, 512)
	count, _ := file.Read(head)
	head = []byte(strings.TrimLeft(string(head[:count]), " \t\r\n"))
	if strings.HasPrefix(string(head), "<?xml") || strings.HasPrefix(string(head), "<items") {
		return "xml"
	}
	if strings.HasPrefix(string(head), "{") {
		return "har"
	}
	if len(head) >= 4 && head[0] == 0x66 && head[1] == 0x85 && head[2] == 0x82 && head[3] == 0x80 {
		return "burp"
	}
	return "burp"
}

func writeJSON(path string, document *Document) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(document)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
}

func sourceToolCounts(items []Item) map[string]int {
	counts := map[string]int{}
	for _, item := range items {
		source := item.SourceTool
		if source == "" {
			source = "unknown"
		}
		counts[source]++
	}
	return counts
}

func filterByHost(items []Item, hosts []string) []Item {
	if len(hosts) == 0 {
		return items
	}
	out := []Item{}
	for _, item := range items {
		if item.Host == nil {
			continue
		}
		host := strings.ToLower(*item.Host)
		for _, wanted := range hosts {
			if strings.Contains(host, strings.ToLower(wanted)) {
				item.ID = len(out) + 1
				out = append(out, item)
				break
			}
		}
	}
	return out
}

func makeBurpInfo(extra *ExtractionResult) *BurpInfo {
	if extra == nil || extra.Header == nil {
		return nil
	}
	header := extra.Header
	return &BurpInfo{
		Magic:           fmt.Sprintf("0x%08x", header.Magic),
		OuterVersion:    int(header.OuterVersion),
		Compatibility:   fmt.Sprintf("0x%08x", uint32(header.Compatibility)),
		SchemaFloor:     int(header.SchemaFloor),
		SchemaCurrent:   int(header.SchemaCurrent),
		ProjectName:     extra.ProjectName,
		BurpVersion:     nil,
		BurpVersionNote: "Burp project files store a format schema, not the exact Burp release. schema_current is reported instead.",
	}
}

func makeMeta(options cliOptions, method, format string, data []byte, items []Item, extra *ExtractionResult, warnings []string) Meta {
	if warnings == nil {
		warnings = []string{}
	}
	sum := sha256.Sum256(data)
	return Meta{
		Tool:             "burp2json",
		ToolVersion:      version,
		SourceFile:       filepath.Base(options.input),
		SourceSHA256:     hex.EncodeToString(sum[:]),
		SourceSize:       int64(len(data)),
		InputFormat:      format,
		ExtractionMethod: method,
		GeneratedAt:      time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00"),
		ReadOnly:         true,
		ItemCount:        len(items),
		SourceToolCounts: sourceToolCounts(items),
		Redacted:         options.redact,
		Burp:             makeBurpInfo(extra),
		Warnings:         warnings,
	}
}

func run(argv []string) int {
	options, err := parseArgs(argv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprintln(os.Stderr, "Try 'burp2json --help' for usage.")
		return 2
	}
	if options.help {
		usage(os.Stdout)
		return 0
	}
	info, err := os.Stat(options.input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: input file not found: %s\n", options.input)
		return 2
	}
	if info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: input is a directory: %s\n", options.input)
		return 2
	}

	format := options.format
	if format == "" {
		format = detectFormat(options.input)
	}
	warnings := []string{}
	extra := &ExtractionResult{
		Collaborator: emptyCollaborator("Collaborator data is only recovered from .burp input."),
		Repeater:     emptyRepeater(),
		Coverage:     map[string]any{},
	}
	var rawItems []*Exchange
	var method string
	switch format {
	case "burp":
		rawItems, method, extra = readBurp(options.input, options.maxBody, &warnings)
	case "xml":
		rawItems, method = readXML(options.input, options.maxBody, &warnings)
	case "har":
		rawItems, method = readHAR(options.input, options.maxBody, &warnings)
	}
	if format == "burp" && method == "burp-heap" {
		rawItems = mergeExchanges(rawItems)
	}
	items := finalizeItems(rawItems, options.maxBody)
	items = filterByHost(items, options.hosts)
	if options.redact {
		redactItems(items)
		redactCollaborator(&extra.Collaborator)
	}
	if len(items) == 0 {
		warnings = append(warnings, "NO HTTP items recovered. Try opening the project in Burp and using "+
			"Proxy > HTTP history > select all > right-click > Save items (XML), "+
			"then run this tool on the XML export.")
	}

	data, err := os.ReadFile(options.input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	meta := makeMeta(options, method, format, data, items, extra, warnings)
	document := &Document{
		AIInstructions: aiInstructions,
		Meta:           meta,
		Collaborator:   extra.Collaborator,
		Repeater:       extra.Repeater,
		Intruder: map[string]any{
			"recovered": false,
			"note": "Intruder attack configuration, payload positions, payload lists and results are " +
				"not stored in the Proxy heap path used here. Export them from Burp if needed.",
		},
		Scanner: map[string]any{
			"recovered": false,
			"note": "Scanner/audit items are not enumerated by this parser. The project root's " +
				"Scanner Dashboard state exists, but task/item ownership is not mapped.",
		},
		Coverage: extra.Coverage,
		Items:    items,
	}
	if len(extra.Collaborator.Interactions) == 0 && extra.Collaborator.Note == "" {
		document.Collaborator = emptyCollaborator("Collaborator data is only recovered from .burp input.")
	}
	if document.Repeater.Tabs == nil {
		document.Repeater.Tabs = []Tab{}
	}
	if document.Repeater.Groups == nil {
		document.Repeater.Groups = []Group{}
	}
	if document.Coverage == nil {
		document.Coverage = map[string]any{}
	}
	if !options.noSummary {
		document.Summary = buildSummary(items)
	}

	outPath := options.output
	if outPath == "" {
		outPath = options.input + ".json"
	}
	written := []string{}
	if options.chunkItems > 0 && len(items) > options.chunkItems {
		parts := (len(items) + options.chunkItems - 1) / options.chunkItems
		base, extension := splitOutputPath(outPath)
		for partIndex := 0; partIndex < parts; partIndex++ {
			start := partIndex * options.chunkItems
			end := start + options.chunkItems
			if end > len(items) {
				end = len(items)
			}
			partNumber := partIndex + 1
			partMeta := meta
			partMeta.Part = partNumber
			partMeta.Parts = parts
			partDocument := &Document{
				AIInstructions: aiInstructions,
				Meta:           partMeta,
				Collaborator:   emptyCollaborator("see part 1"),
				Repeater:       emptyRepeater(),
				Intruder:       map[string]any{"recovered": false, "note": "see part 1"},
				Scanner:        map[string]any{"recovered": false, "note": "see part 1"},
				Coverage:       map[string]any{},
				Items:          items[start:end],
			}
			if partNumber == 1 {
				if !options.noSummary {
					partDocument.Summary = document.Summary
				}
				partDocument.Collaborator = document.Collaborator
				partDocument.Repeater = document.Repeater
				partDocument.Intruder = document.Intruder
				partDocument.Scanner = document.Scanner
				partDocument.Coverage = document.Coverage
			}
			path := fmt.Sprintf("%s_part%03d%s", base, partNumber, extension)
			if err := writeJSON(path, partDocument); err != nil {
				fmt.Fprintf(os.Stderr, "error writing %s: %s\n", path, err)
				return 1
			}
			written = append(written, path)
		}
	} else {
		if err := writeJSON(outPath, document); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %s\n", outPath, err)
			return 1
		}
		written = append(written, outPath)
	}

	fmt.Fprintf(os.Stderr, "method=%s items=%d\n", method, len(items))
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "warning: "+warning)
	}
	for _, path := range written {
		fmt.Println(path)
	}
	return 0
}

func splitOutputPath(path string) (string, string) {
	extension := filepath.Ext(path)
	base := strings.TrimSuffix(path, extension)
	if base == "" {
		base = path
	}
	if extension == "" {
		extension = ".json"
	}
	return base, extension
}

func main() {
	os.Exit(run(os.Args[1:]))
}
