package burp2json

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
)

var (
	responseLineRE = regexp.MustCompile(`^HTTP/(\S+)\s+([0-9]{3})\s*(.*)$`)
	jwtRE          = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}`)
	secretKVRE     = regexp.MustCompile(`(?i)("?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)"?\s*[:=]\s*"?)([^"&\s,}]{3,})`)
)

func decodeChunked(data []byte) ([]byte, bool) {
	out := make([]byte, 0, len(data))
	pos := 0
	for {
		eol := bytes.IndexByte(data[pos:], '\n')
		if eol < 0 {
			return out, false
		}
		eol += pos
		sizeText := strings.TrimSpace(string(data[pos:eol]))
		if semi := strings.IndexByte(sizeText, ';'); semi >= 0 {
			sizeText = sizeText[:semi]
		}
		size, err := strconv.ParseInt(sizeText, 16, 64)
		if err != nil || size < 0 {
			return out, false
		}
		pos = eol + 1
		if size == 0 {
			return out, true
		}
		if size > int64(len(data)-pos) {
			return out, false
		}
		out = append(out, data[pos:pos+int(size)]...)
		pos += int(size)
		if pos+1 < len(data) && data[pos] == '\r' && data[pos+1] == '\n' {
			pos += 2
		} else if pos < len(data) && data[pos] == '\n' {
			pos++
		}
	}
}

func decompressBody(body []byte, encoding string) ([]byte, string) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" {
		return body, ""
	}
	var (
		reader io.Reader
		closer io.Closer
	)
	switch {
	case strings.Contains(enc, "gzip"):
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, "decompress failed: " + err.Error()
		}
		reader, closer = zr, zr
	case strings.Contains(enc, "deflate"):
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			zr = nil
		}
		if zr != nil {
			reader, closer = zr, zr
		} else {
			fr := flate.NewReader(bytes.NewReader(body))
			reader, closer = fr, fr
		}
	case strings.Contains(enc, "br"):
		reader = brotli.NewReader(bytes.NewReader(body))
	case strings.Contains(enc, "zstd"):
		return body, "zstd body left compressed (not supported)"
	default:
		return body, ""
	}
	if closer != nil {
		defer closer.Close()
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		return body, "decompress failed: " + err.Error()
	}
	return out, ""
}

func headerValue(headers [][2]string, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header[0], name) {
			return header[1]
		}
	}
	return ""
}

func latin1String(data []byte) string {
	var builder strings.Builder
	builder.Grow(len(data))
	for _, value := range data {
		builder.WriteRune(rune(value))
	}
	return builder.String()
}

func encodeBody(body []byte, maxBody int) BodyFields {
	if len(body) == 0 {
		return BodyFields{Body: "", BodyEncoding: "utf-8", BodyLength: 0, BodyTruncated: false}
	}
	truncated := len(body) > maxBody
	shown := body
	if truncated {
		shown = body[:maxBody]
	}
	controls := 0
	for _, b := range shown {
		if b < 9 || (b > 13 && b < 32) {
			controls++
		}
	}
	if utf8.Valid(shown) && controls < maxInt(1, len(shown)*5/100) {
		return BodyFields{Body: string(shown), BodyEncoding: "utf-8",
			BodyLength: len(body), BodyTruncated: truncated}
	}
	if controls < len(shown)*5/100 {
		var b strings.Builder
		b.Grow(len(shown))
		for _, c := range shown {
			b.WriteRune(rune(c))
		}
		return BodyFields{Body: b.String(), BodyEncoding: "latin-1",
			BodyLength: len(body), BodyTruncated: truncated}
	}
	return BodyFields{Body: base64.StdEncoding.EncodeToString(shown), BodyEncoding: "base64",
		BodyLength: len(body), BodyTruncated: truncated}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type parsedMessage struct {
	Request  *RequestMessage
	Response *ResponseMessage
	Consumed int
	Warnings []string
}

func parseHTTP(raw []byte, isRequest bool, maxBody int, strictEnd *int) (*parsedMessage, bool) {
	sep := bytes.Index(raw, []byte("\r\n\r\n"))
	sepLen := 4
	if sep < 0 {
		sep = bytes.Index(raw, []byte("\n\n"))
		sepLen = 2
	}
	if sep < 0 {
		return nil, false
	}
	head := latin1String(raw[:sep])
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	first := strings.TrimSpace(lines[0])
	headers := make([][2]string, 0, len(lines)-1)
	for _, line := range lines[1:] {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		headers = append(headers, [2]string{strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])})
	}

	bodyStart := sep + sepLen
	rest := raw[bodyStart:]
	contentLength := headerValue(headers, "content-length")
	transferEncoding := strings.ToLower(headerValue(headers, "transfer-encoding"))
	consumedExtra := 0
	var body []byte
	if strings.Contains(transferEncoding, "chunked") {
		var complete bool
		body, complete = decodeChunked(rest)
		if !complete {
			// keep the partial body when a chunked stream is incomplete
		}
		if strictEnd == nil {
			consumedExtra = len(rest)
		} else {
			consumedExtra = minInt(len(rest), maxInt(*strictEnd-bodyStart, 0))
		}
	} else if n, err := strconv.Atoi(contentLength); err == nil && n >= 0 {
		if n > len(rest) {
			body = rest
		} else {
			body = rest[:n]
		}
		consumedExtra = len(body)
	} else if strictEnd != nil {
		n := maxInt(*strictEnd-bodyStart, 0)
		if n > len(rest) {
			n = len(rest)
		}
		body = rest[:n]
		consumedExtra = len(body)
	}

	warnings := []string{}
	if strings.Contains(transferEncoding, "chunked") {
		if _, complete := decodeChunked(rest); !complete {
			warnings = append(warnings, "chunked body incomplete")
		}
	} else if n, err := strconv.Atoi(contentLength); err == nil && n >= 0 && len(rest) < n {
		warnings = append(warnings, fmt.Sprintf("body shorter than Content-Length (%d < %d)", len(rest), n))
	}
	decoded, warning := decompressBody(body, headerValue(headers, "content-encoding"))
	if warning != "" {
		warnings = append(warnings, warning)
	}
	bodyFields := encodeBody(decoded, maxBody)
	bodyFields.Headers = headers
	contentType := headerValue(headers, "content-type")
	if idx := strings.IndexByte(contentType, ';'); idx >= 0 {
		contentType = contentType[:idx]
	}
	if contentType != "" {
		bodyFields.ContentType = strings.ToLower(strings.TrimSpace(contentType))
	}

	if isRequest {
		parts := strings.Split(first, " ")
		if len(parts) < 3 {
			return nil, false
		}
		req := &RequestMessage{
			Method:      parts[0],
			Target:      parts[1],
			HTTPVersion: parts[len(parts)-1],
			RequestLine: first,
			BodyFields:  bodyFields,
		}
		return &parsedMessage{Request: req, Consumed: bodyStart + consumedExtra,
			Warnings: warnings}, true
	}

	match := responseLineRE.FindStringSubmatch(first)
	if match == nil {
		return nil, false
	}
	status, _ := strconv.Atoi(match[2])
	resp := &ResponseMessage{
		Status:      status,
		Reason:      match[3],
		HTTPVersion: match[1],
		StatusLine:  first,
		BodyFields:  bodyFields,
	}
	return &parsedMessage{Response: resp, Consumed: bodyStart + consumedExtra,
		Warnings: warnings}, true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseQueryPairs(raw string) [][2]any {
	out := [][2]any{}
	if raw == "" {
		return out
	}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		key, value := part, ""
		if idx := strings.IndexByte(part, '='); idx >= 0 {
			key, value = part[:idx], part[idx+1:]
		}
		if decoded, err := url.QueryUnescape(key); err == nil {
			key = decoded
		}
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = decoded
		}
		out = append(out, [2]any{key, value})
	}
	return out
}

func decodeJSONParams(body string) [][2]any {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil {
		return [][2]any{}
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return [][2]any{}
	}
	out := [][2]any{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return out
		}
		key, ok := keyToken.(string)
		if !ok {
			return out
		}
		var value any
		if err := dec.Decode(&value); err != nil {
			return out
		}
		out = append(out, [2]any{key, paramValue(value)})
	}
	return out
}

func paramValue(value any) any {
	switch v := value.(type) {
	case nil, string, bool:
		return v
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		if f, err := v.Float64(); err == nil {
			return f
		}
		return v.String()
	case []any:
		return "<list>"
	case map[string]any:
		return "<dict>"
	default:
		return fmt.Sprintf("<%T>", v)
	}
}

func enrichRequest(req *RequestMessage, hostHint string) {
	if req == nil {
		return
	}
	cookies := map[string]string{}
	for _, header := range req.Headers {
		if !strings.EqualFold(header[0], "cookie") {
			continue
		}
		for _, part := range strings.Split(header[1], ";") {
			if idx := strings.IndexByte(part, '='); idx >= 0 {
				cookies[strings.TrimSpace(part[:idx])] = strings.TrimSpace(part[idx+1:])
			}
		}
	}
	parsed, err := url.Parse(req.Target)
	path := req.Target
	query := ""
	if err == nil {
		path = parsed.Path
		if path == "" {
			path = "/"
		}
		query = parsed.RawQuery
	} else if idx := strings.IndexByte(path, '?'); idx >= 0 {
		query = path[idx+1:]
		path = path[:idx]
	}
	if path == "" {
		path = "/"
	}
	req.Path = path
	req.QueryParams = parseQueryPairs(query)
	req.Cookies = cookies
	req.BodyParams = [][2]any{}
	if req.Body != "" && req.BodyEncoding != "base64" {
		switch {
		case req.ContentType == "application/x-www-form-urlencoded":
			req.BodyParams = parseQueryPairs(req.Body)
		case strings.HasSuffix(req.ContentType, "json"):
			req.BodyParams = decodeJSONParams(req.Body)
		}
	}
	req.HostHeader = headerValue(req.Headers, "host")
	if req.HostHeader == "" {
		req.HostHeader = hostHint
	}
}

func splitHostPort(hostHeader string) (string, int) {
	if hostHeader == "" {
		return "", 0
	}
	if strings.HasPrefix(hostHeader, "[") {
		end := strings.IndexByte(hostHeader, ']')
		if end >= 0 {
			host := hostHeader[1:end]
			rest := hostHeader[end+1:]
			if strings.HasPrefix(rest, ":") {
				if port, err := strconv.Atoi(rest[1:]); err == nil {
					return host, port
				}
			}
			return host, 0
		}
	}
	if idx := strings.LastIndexByte(hostHeader, ':'); idx >= 0 {
		if port, err := strconv.Atoi(hostHeader[idx+1:]); err == nil {
			return hostHeader[:idx], port
		}
	}
	return hostHeader, 0
}

func serviceFromMeta(meta map[string]any) *Service {
	if meta == nil {
		return nil
	}
	switch value := meta["service"].(type) {
	case *Service:
		return value
	case Service:
		copy := value
		return &copy
	}
	return nil
}

func inferURL(req *RequestMessage, meta map[string]any, defaultScheme string, defaultPort int) (string, string, int, string) {
	if req == nil {
		return "", "", 0, ""
	}
	target := req.Target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		parsed, err := url.Parse(target)
		if err == nil {
			scheme := parsed.Scheme
			if scheme == "" {
				scheme = "http"
			}
			host := parsed.Hostname()
			port := 0
			if p := parsed.Port(); p != "" {
				port, _ = strconv.Atoi(p)
			}
			if port == 0 {
				if scheme == "https" {
					port = 443
				} else {
					port = 80
				}
			}
			return target, host, port, scheme
		}
	}

	service := serviceFromMeta(meta)
	host, port := "", 0
	if service != nil {
		host = service.Host
		if service.Port != nil {
			port = *service.Port
		}
	}
	hostHeader := headerValue(req.Headers, "host")
	if host == "" {
		host, port = splitHostPort(hostHeader)
	}

	var scheme string
	tls := false
	if service != nil && service.TLS != nil {
		tls = *service.TLS
	}
	if defaultScheme == "http" || defaultScheme == "https" {
		scheme = defaultScheme
	} else if service != nil && service.TLS != nil {
		if tls {
			scheme = "https"
		} else {
			scheme = "http"
		}
	} else if port != 0 {
		if port == 443 || port == 8443 {
			scheme = "https"
		} else {
			scheme = "http"
		}
	} else if req.HTTPVersion == "2" || req.HTTPVersion == "HTTP/2" {
		scheme = "https"
	} else {
		scheme = "http"
	}

	if defaultPort != 0 {
		port = defaultPort
	}
	if host == "" {
		return "", "", 0, ""
	}
	if port == 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	displayHost := host
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		displayHost = fmt.Sprintf("%s:%d", host, port)
	}
	switch {
	case strings.HasPrefix(target, "/"):
		return fmt.Sprintf("%s://%s%s", scheme, displayHost, target), host, port, scheme
	case target != "":
		return fmt.Sprintf("%s://%s/%s", scheme, displayHost, target), host, port, scheme
	default:
		return fmt.Sprintf("%s://%s/", scheme, displayHost), host, port, scheme
	}
}

func timeISO(epochMS int64) *string {
	t := time.UnixMilli(epochMS).UTC()
	var text string
	if t.Nanosecond()/1000 == 0 {
		text = t.Format("2006-01-02T15:04:05+00:00")
	} else {
		text = t.Format("2006-01-02T15:04:05.000000+00:00")
	}
	return &text
}
