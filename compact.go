package main

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Compact output is deliberately shaped for an LLM reader rather than a human.
// It uses a schema-once, positional-row layout, a global string table, and flat
// header index pairs. Repeating a key on every item/header is expensive in tokens.
const (
	compactFormat = "b2j-sir/1"
	recallFormat  = "b2j-recall/1"

	defaultBodyPreview = 1024
	defaultHeaderMax   = 512
)

const compactRead = "b2j-sir/1: schema-once JSON for LLMs. " +
	"'schema' maps every positional array to its fields. " +
	"'strings' is a global table. Indexes: item.tool, item.also[], item.title, item.comment, and flat header pairs. " +
	"Other strings are direct values. Headers are [nameIndex,valueIndex,...] in wire order (duplicates preserved). " +
	"Request row: [method,target,http_version,headers,body,body_encoding,orig_bytes,ref]. " +
	"Response row: [reason,http_version,headers,body,body_encoding,orig_bytes,ref]. " +
	"body_encoding null means utf-8; orig_bytes non-null means truncated or elided; ref is a recall sidecar key. " +
	"base64 bodies are inlined only with --full; otherwise read them from the recall sidecar. " +
	"time is Unix milliseconds. status is the response code. item.id is used by summary redirects/errors. " +
	"URL contains scheme/host/port/path/query; path, query params, cookies and body params are derivable. " +
	"source tools: proxy, repeater, site-map, har, logger, unknown; item.also lists other tools. " +
	"summary shapes: host=[host,count,ports,protocols], endpoint=[host,method,path,count,[[status,count]],params], " +
	"redirect=[itemId,status,location], error=[itemId,status]. " +
	"collaborator interactions are [type,host,method,path,responseStatus,responseServer,request,response]. " +
	"Values marked [REDACTED] were removed by the user. " +
	"Review for access control, IDOR, auth/session handling, injection points, CORS, security headers, " +
	"information disclosure, and business-logic flaws. Intruder/Scanner configuration is not recovered."

const recallRead = "b2j-recall/1: full values omitted from the b2j-sir/1 file. " +
	"'strings' maps s<index> to the untruncated value for that strings[] index. " +
	"'bodies' maps <itemId>r/<itemId>p to the full request/response body available to the converter, " +
	"and c<n>r/c<n>p for Collaborator interaction n. " +
	"A body may already be shorter than orig_bytes if --max-body capped it before compaction."

type compactOptions struct {
	BodyPreview int
	HeaderMax   int
	KeepBase64  bool
	RecallName  string
}

type CompactDocument struct {
	Format       string              `json:"format"`
	Read         string              `json:"read"`
	Recall       string              `json:"recall,omitempty"`
	Meta         CompactMeta         `json:"meta"`
	Schema       CompactSchema       `json:"schema"`
	Strings      []string            `json:"strings"`
	Items        [][]any             `json:"items"`
	Summary      *CompactSummary     `json:"summary,omitempty"`
	Collaborator CompactCollaborator `json:"collaborator"`
	Repeater     RepeaterInfo        `json:"repeater"`
	Coverage     map[string]any      `json:"coverage"`
}

type CompactMeta struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Source   string         `json:"source"`
	SHA256   string         `json:"sha256"`
	Bytes    int64          `json:"bytes"`
	Input    string         `json:"input"`
	Method   string         `json:"method"`
	At       string         `json:"at"`
	ReadOnly bool           `json:"read_only,omitempty"`
	Items    int            `json:"items"`
	Tools    map[string]int `json:"tools,omitempty"`
	Redacted bool           `json:"redacted,omitempty"`
	Burp     *CompactBurp   `json:"burp,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
	Part     int            `json:"part,omitempty"`
	Parts    int            `json:"parts,omitempty"`
}

type CompactBurp struct {
	Magic       string  `json:"magic"`
	Outer       int     `json:"outer_version"`
	Compat      string  `json:"compat"`
	Schema      int     `json:"schema"`
	SchemaFloor int     `json:"schema_floor,omitempty"`
	Project     *string `json:"project,omitempty"`
}

type CompactSchema struct {
	Item        []string `json:"item"`
	Request     []string `json:"request"`
	Response    []string `json:"response"`
	Interaction []string `json:"interaction"`
	Host        []string `json:"host"`
	Endpoint    []string `json:"endpoint"`
}

type CompactSummary struct {
	Total           int            `json:"total"`
	Hosts           [][]any        `json:"hosts,omitempty"`
	Endpoints       [][]any        `json:"endpoints,omitempty"`
	Params          []string       `json:"params,omitempty"`
	Methods         map[string]int `json:"methods,omitempty"`
	Status          map[string]int `json:"status,omitempty"`
	ContentTypes    map[string]int `json:"content_types,omitempty"`
	Tech            map[string]int `json:"tech,omitempty"`
	Cookies         []string       `json:"cookies,omitempty"`
	Auth            []string       `json:"auth,omitempty"`
	MissingSecurity map[string]int `json:"missing_security,omitempty"`
	Redirects       [][]any        `json:"redirects,omitempty"`
	ClientErrors    [][]any        `json:"errors_4xx,omitempty"`
	ServerErrors    [][]any        `json:"errors_5xx,omitempty"`
	Highlights      map[string]int `json:"highlights,omitempty"`
}

type CompactCollaborator struct {
	Domains      []string `json:"domains,omitempty"`
	Types        []string `json:"types,omitempty"`
	Interactions [][]any  `json:"interactions,omitempty"`
	Note         string   `json:"note,omitempty"`
}

type compactRecall struct {
	Format  string            `json:"format"`
	Read    string            `json:"read"`
	Strings map[string]string `json:"strings,omitempty"`
	Bodies  map[string]string `json:"bodies,omitempty"`
}

type compactBuilder struct {
	options  compactOptions
	strings  []string
	interned map[string]int
	recall   compactRecall
}

func newCompactBuilder(options compactOptions) *compactBuilder {
	return &compactBuilder{
		options:  options,
		strings:  []string{},
		interned: map[string]int{},
		recall: compactRecall{
			Format:  recallFormat,
			Read:    recallRead,
			Strings: map[string]string{},
			Bodies:  map[string]string{},
		},
	}
}

func (builder *compactBuilder) intern(value string) int {
	if index, ok := builder.interned[value]; ok {
		return index
	}
	shown := value
	if builder.options.HeaderMax > 0 && len(value) > builder.options.HeaderMax {
		shown = truncateUTF8(value, builder.options.HeaderMax) +
			"…[" + strconv.Itoa(len(value)) + "]"
	}
	index := len(builder.strings)
	builder.strings = append(builder.strings, shown)
	builder.interned[value] = index
	if shown != value {
		builder.recall.Strings["s"+strconv.Itoa(index)] = value
	}
	return index
}

// Short semantic strings (header names, source tools) stay readable even when
// header values are heavily capped.
func (builder *compactBuilder) internRaw(value string) int {
	if index, ok := builder.interned[value]; ok {
		return index
	}
	index := len(builder.strings)
	builder.strings = append(builder.strings, value)
	builder.interned[value] = index
	return index
}

func (builder *compactBuilder) headers(headers [][2]string) any {
	if len(headers) == 0 {
		return nil
	}
	pairs := make([]int, 0, len(headers)*2)
	for _, header := range headers {
		pairs = append(pairs, builder.internRaw(header[0]), builder.intern(header[1]))
	}
	return pairs
}

func (builder *compactBuilder) body(fields *BodyFields, ref string) []any {
	if fields == nil {
		return nil
	}
	body := fields.Body
	var encoding any
	if fields.BodyEncoding != "" && fields.BodyEncoding != "utf-8" {
		encoding = fields.BodyEncoding
	}
	if fields.BodyEncoding == "base64" && !builder.options.KeepBase64 {
		// A base64 prefix is not useful to an LLM and tokenizes badly. Keep it
		// addressable through the recall sidecar instead of inlining it.
		var original any
		var recallRef any
		if fields.BodyLength > 0 {
			original = fields.BodyLength
		}
		if fields.Body != "" {
			builder.recall.Bodies[ref] = fields.Body
			recallRef = ref
		}
		return []any{"", encoding, original, recallRef}
	}
	cut := builder.options.BodyPreview > 0 && len(body) > builder.options.BodyPreview
	if cut {
		body = truncateUTF8(body, builder.options.BodyPreview)
	}
	var original any
	if cut || fields.BodyTruncated {
		original = fields.BodyLength
	}
	var recallRef any
	if cut {
		builder.recall.Bodies[ref] = fields.Body
		recallRef = ref
	}
	return []any{body, encoding, original, recallRef}
}

func (builder *compactBuilder) request(message *RequestMessage, key string) any {
	if message == nil {
		return nil
	}
	body := builder.body(&message.BodyFields, key+"r")
	return []any{
		message.Method,
		message.Target,
		optionalString(message.HTTPVersion),
		builder.headers(message.Headers),
		body[0], body[1], body[2], body[3],
	}
}

func (builder *compactBuilder) response(message *ResponseMessage, key string) any {
	if message == nil {
		return nil
	}
	body := builder.body(&message.BodyFields, key+"p")
	return []any{
		optionalString(message.Reason),
		optionalString(message.HTTPVersion),
		builder.headers(message.Headers),
		body[0], body[1], body[2], body[3],
	}
}

func (builder *compactBuilder) item(item Item) []any {
	source := item.SourceTool
	if source == "" {
		source = "unknown"
	}
	status := item.Status
	if item.Response != nil && item.Response.Status != 0 {
		status = intPtr(item.Response.Status)
	}
	var also any
	if len(item.AlsoSeenIn) > 0 {
		seen := make([]int, 0, len(item.AlsoSeenIn))
		for _, sourceTool := range item.AlsoSeenIn {
			seen = append(seen, builder.internRaw(sourceTool))
		}
		also = seen
	}
	var title any
	if value := metaStringPtr(item.Metadata, "title"); value != nil && *value != "" {
		title = builder.intern(*value)
	}
	var comment any
	if item.Comment != nil && *item.Comment != "" {
		comment = builder.intern(*item.Comment)
	}
	var warningList any
	if len(item.Warnings) > 0 {
		warningList = item.Warnings
	}
	key := strconv.Itoa(item.ID)
	return []any{
		item.ID,
		builder.internRaw(source),
		also,
		optionalInt64(item.Time),
		optionalStringPtr(compactURL(item)),
		optionalInt(status),
		title,
		comment,
		optionalStringPtr(item.Highlight),
		builder.request(item.Request, key),
		builder.response(item.Response, key),
		warningList,
	}
}

func (builder *compactBuilder) interaction(interaction Interaction, index int) []any {
	key := "c" + strconv.Itoa(index)
	return []any{
		interaction.Type,
		interaction.Host,
		interaction.Method,
		interaction.Path,
		optionalInt(interaction.ResponseStatus),
		optionalStringPtr(interaction.ResponseServer),
		builder.request(interaction.Request, key),
		builder.response(interaction.Response, key),
	}
}

func compactURL(item Item) *string {
	if item.URL != nil && *item.URL != "" {
		return item.URL
	}
	if item.Host == nil || *item.Host == "" {
		return nil
	}
	scheme := "https"
	if item.Protocol != nil && *item.Protocol != "" {
		scheme = *item.Protocol
	}
	path := "/"
	if item.Path != nil && *item.Path != "" {
		path = *item.Path
	}
	port := ""
	if item.Port != nil && *item.Port != 0 &&
		!((scheme == "https" && *item.Port == 443) || (scheme == "http" && *item.Port == 80)) {
		port = ":" + strconv.Itoa(*item.Port)
	}
	value := scheme + "://" + *item.Host + port + path
	return &value
}

func compactMeta(meta Meta) CompactMeta {
	out := CompactMeta{
		Tool:     meta.Tool,
		Version:  meta.ToolVersion,
		Source:   meta.SourceFile,
		SHA256:   meta.SourceSHA256,
		Bytes:    meta.SourceSize,
		Input:    meta.InputFormat,
		Method:   meta.ExtractionMethod,
		At:       meta.GeneratedAt,
		ReadOnly: meta.ReadOnly,
		Items:    meta.ItemCount,
		Tools:    meta.SourceToolCounts,
		Redacted: meta.Redacted,
	}
	if len(meta.Warnings) > 0 {
		out.Warnings = meta.Warnings
	}
	if meta.Part != 0 {
		out.Part = meta.Part
		out.Parts = meta.Parts
	}
	if meta.Burp != nil {
		burp := &CompactBurp{
			Magic:   meta.Burp.Magic,
			Outer:   meta.Burp.OuterVersion,
			Compat:  meta.Burp.Compatibility,
			Schema:  meta.Burp.SchemaCurrent,
			Project: meta.Burp.ProjectName,
		}
		if meta.Burp.SchemaFloor != meta.Burp.SchemaCurrent {
			burp.SchemaFloor = meta.Burp.SchemaFloor
		}
		out.Burp = burp
	}
	return out
}

func compactSummary(summary *Summary) *CompactSummary {
	if summary == nil {
		return nil
	}
	out := &CompactSummary{
		Total:           summary.TotalItems,
		Methods:         summary.Methods,
		Status:          summary.StatusCodes,
		ContentTypes:    summary.ContentTypes,
		Tech:            summary.TechnologyHeaders,
		Cookies:         summary.CookieNamesSeen,
		Auth:            summary.AuthHeaderNamesSeen,
		MissingSecurity: summary.ResponsesMissingSecurityHeaders,
		Highlights:      summary.Highlights,
	}
	if len(summary.HostDetails) > 0 {
		out.Hosts = make([][]any, 0, len(summary.HostDetails))
		for _, host := range summary.HostDetails {
			out.Hosts = append(out.Hosts, []any{host.Host, host.Count, host.Ports, host.Protocols})
		}
	}
	if len(summary.Endpoints) > 0 {
		out.Endpoints = make([][]any, 0, len(summary.Endpoints))
		for _, endpoint := range summary.Endpoints {
			statuses := make([][]any, 0, len(endpoint.Statuses))
			codes := make([]string, 0, len(endpoint.Statuses))
			for code := range endpoint.Statuses {
				codes = append(codes, code)
			}
			sort.Slice(codes, func(i, j int) bool {
				left, leftErr := strconv.Atoi(codes[i])
				right, rightErr := strconv.Atoi(codes[j])
				if leftErr == nil && rightErr == nil {
					return left < right
				}
				return codes[i] < codes[j]
			})
			for _, code := range codes {
				value, err := strconv.Atoi(code)
				if err == nil {
					statuses = append(statuses, []any{value, endpoint.Statuses[code]})
				} else {
					statuses = append(statuses, []any{code, endpoint.Statuses[code]})
				}
			}
			out.Endpoints = append(out.Endpoints,
				[]any{endpoint.Host, endpoint.Method, endpoint.Path, endpoint.Count, statuses, endpoint.Params})
		}
	}
	if len(summary.ParameterNames) > 0 {
		out.Params = summary.ParameterNames
	}
	if len(summary.Redirects) > 0 {
		out.Redirects = make([][]any, 0, len(summary.Redirects))
		for _, redirect := range summary.Redirects {
			out.Redirects = append(out.Redirects,
				[]any{redirect.ID, optionalInt(redirect.Status), optionalStringPtr(redirect.Location)})
		}
	}
	if len(summary.ClientErrors) > 0 {
		out.ClientErrors = compactErrors(summary.ClientErrors)
	}
	if len(summary.ServerErrors) > 0 {
		out.ServerErrors = compactErrors(summary.ServerErrors)
	}
	return out
}

func compactErrors(errors []ErrorInfo) [][]any {
	out := make([][]any, 0, len(errors))
	for _, item := range errors {
		out = append(out, []any{item.ID, optionalInt(item.Status)})
	}
	return out
}

func compactCollaborator(collaborator *Collaborator, builder *compactBuilder) CompactCollaborator {
	out := CompactCollaborator{
		Domains: collaborator.DomainsSeen,
		Types:   collaborator.InteractionTypesSeen,
		Note:    collaborator.Note,
	}
	if len(collaborator.Interactions) > 0 {
		out.Interactions = make([][]any, 0, len(collaborator.Interactions))
		for index, interaction := range collaborator.Interactions {
			out.Interactions = append(out.Interactions, builder.interaction(interaction, index+1))
		}
	}
	return out
}

func compactSchemaDefinition() CompactSchema {
	return CompactSchema{
		Item: []string{
			"id", "tool", "also", "time", "url", "status", "title", "comment",
			"highlight", "request", "response", "warnings",
		},
		Request: []string{
			"method", "target", "http_version", "headers",
			"body", "body_encoding", "orig_bytes", "ref",
		},
		Response: []string{
			"reason", "http_version", "headers",
			"body", "body_encoding", "orig_bytes", "ref",
		},
		Interaction: []string{
			"type", "host", "method", "path", "response_status",
			"response_server", "request", "response",
		},
		Host:     []string{"host", "count", "ports", "protocols"},
		Endpoint: []string{"host", "method", "path", "count", "statuses", "params"},
	}
}

func buildCompactDocument(document *Document, options compactOptions) (*CompactDocument, *compactRecall) {
	builder := newCompactBuilder(options)
	items := make([][]any, 0, len(document.Items))
	for _, item := range document.Items {
		items = append(items, builder.item(item))
	}
	coverage := document.Coverage
	if coverage == nil {
		coverage = map[string]any{}
	}
	summary := compactSummary(document.Summary)
	collaborator := compactCollaborator(&document.Collaborator, builder)
	out := &CompactDocument{
		Format:       compactFormat,
		Read:         compactRead,
		Meta:         compactMeta(document.Meta),
		Schema:       compactSchemaDefinition(),
		Strings:      builder.strings,
		Items:        items,
		Summary:      summary,
		Collaborator: collaborator,
		Repeater:     document.Repeater,
		Coverage:     coverage,
	}
	if len(builder.recall.Strings) > 0 || len(builder.recall.Bodies) > 0 {
		out.Recall = options.RecallName
		return out, &builder.recall
	}
	return out, nil
}

func optionalString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func optionalStringPtr(value *string) any {
	if value == nil || *value == "" {
		return nil
	}
	return *value
}

func optionalInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func optionalInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func truncateUTF8(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

func recallOutputPath(path string) string {
	extension := filepath.Ext(path)
	base := strings.TrimSuffix(path, extension)
	if base == "" {
		base = path
	}
	return base + ".recall.json"
}
