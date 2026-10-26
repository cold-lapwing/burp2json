package burp2json

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var regexpSensitiveKey = regexp.MustCompile(`(?i)pass|secret|token|key|auth|session|jwt`)

func exchangeKey(exchange *Exchange) string {
	request := exchange.RequestRaw
	response := exchange.ResponseRaw
	hash := sha256.New()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(request)))
	hash.Write(length[:])
	hash.Write(request)
	binary.BigEndian.PutUint64(length[:], uint64(len(response)))
	hash.Write(length[:])
	hash.Write(response)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func sourcePriority(source string) int {
	switch source {
	case "proxy":
		return 0
	case "repeater":
		return 1
	case "site-map":
		return 2
	case "unknown":
		return 3
	default:
		return 4
	}
}

func mergeExchanges(exchanges []*Exchange) []*Exchange {
	merged := map[string]*Exchange{}
	order := []string{}
	for _, exchange := range exchanges {
		key := exchangeKey(exchange)
		current, exists := merged[key]
		if !exists {
			copy := *exchange
			copy.AlsoSeenIn = []string{}
			merged[key] = &copy
			order = append(order, key)
			continue
		}
		if current.Source != exchange.Source {
			current.AlsoSeenIn = append(current.AlsoSeenIn, exchange.Source)
		}
		if sourcePriority(exchange.Source) < sourcePriority(current.Source) {
			oldSource := current.Source
			oldAlso := append([]string{}, current.AlsoSeenIn...)
			copy := *exchange
			also := append(oldAlso, oldSource)
			copy.AlsoSeenIn = uniqueSorted(also)
			merged[key] = &copy
		}
	}
	out := make([]*Exchange, 0, len(order))
	for _, key := range order {
		exchange := merged[key]
		exchange.AlsoSeenIn = uniqueSorted(exchange.AlsoSeenIn)
		out = append(out, exchange)
	}
	return out
}

func uniqueSorted(values []string) []string {
	set := map[string]bool{}
	for _, value := range values {
		if value != "" {
			set[value] = true
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeSource(value string) string {
	text := strings.ToLower(strings.TrimSpace(value))
	text = strings.ReplaceAll(text, "_", "-")
	text = strings.ReplaceAll(text, " ", "-")
	aliases := map[string]string{
		"target": "site-map", "sitemap": "site-map",
		"proxy-history": "proxy", "http-history": "proxy",
		"xml-export": "unknown",
	}
	if alias, ok := aliases[text]; ok {
		return alias
	}
	if text == "" {
		return "unknown"
	}
	return text
}

func metaStringPtr(meta map[string]any, key string) *string {
	if meta == nil {
		return nil
	}
	switch value := meta[key].(type) {
	case *string:
		return value
	case string:
		return &value
	}
	return nil
}

func metaIntPtr(meta map[string]any, key string) *int {
	if meta == nil {
		return nil
	}
	switch value := meta[key].(type) {
	case *int:
		return value
	case int:
		return &value
	case *int64:
		v := int(*value)
		return &v
	case int64:
		v := int(value)
		return &v
	case *int16:
		v := int(*value)
		return &v
	case int16:
		v := int(value)
		return &v
	case *byte:
		v := int(*value)
		return &v
	case byte:
		v := int(value)
		return &v
	case json.Number:
		if i, err := value.Int64(); err == nil {
			v := int(i)
			return &v
		}
	}
	return nil
}

func metaInt64Ptr(meta map[string]any, key string) *int64 {
	if meta == nil {
		return nil
	}
	switch value := meta[key].(type) {
	case *int64:
		return value
	case int64:
		return &value
	case *int:
		v := int64(*value)
		return &v
	case int:
		v := int64(value)
		return &v
	case json.Number:
		if i, err := value.Int64(); err == nil {
			return &i
		}
	}
	return nil
}

func finalizeItems(rawItems []*Exchange, maxBody int) []Item {
	out := []Item{}
	for _, raw := range rawItems {
		request := raw.Request
		response := raw.Response
		warnings := append([]string{}, raw.Warnings...)
		if len(raw.RequestRaw) > 0 && request == nil {
			if parsed, ok := parseHTTP(raw.RequestRaw, true, maxBody, intPtr(len(raw.RequestRaw))); ok {
				request = parsed.Request
				warnings = append(warnings, parsed.Warnings...)
			}
		}
		if len(raw.ResponseRaw) > 0 && response == nil {
			if parsed, ok := parseHTTP(raw.ResponseRaw, false, maxBody, intPtr(len(raw.ResponseRaw))); ok {
				response = parsed.Response
				warnings = append(warnings, parsed.Warnings...)
			}
		}
		if request == nil && response == nil {
			continue
		}
		if request != nil {
			enrichRequest(request, "")
		}
		url, host, port, scheme := inferURL(request, raw.Meta, raw.Protocol, raw.Port)
		if host == "" {
			host = raw.Host
		}
		if port == 0 && raw.Port != 0 {
			port = raw.Port
		}
		if scheme == "" {
			scheme = raw.Protocol
		}
		var status *int
		if response != nil {
			if response.Status != 0 {
				status = intPtr(response.Status)
			}
		}
		if status == nil {
			status = metaIntPtr(raw.Meta, "status")
		}
		comment := raw.Comment
		if comment == nil || *comment == "" {
			comment = metaStringPtr(raw.Meta, "comment")
		}
		timeValue := raw.Time
		if timeValue == nil || *timeValue == 0 {
			timeValue = metaInt64Ptr(raw.Meta, "time_epoch_ms")
		}
		method := raw.Method
		if request != nil {
			method = request.Method
		}
		path := raw.Path
		if request != nil {
			path = request.Path
		}
		metadata := raw.Meta
		if metadata == nil {
			metadata = map[string]any{}
		}
		item := Item{
			ID:         len(out) + 1,
			SourceTool: normalizeSource(raw.Source),
			AlsoSeenIn: uniqueSorted(raw.AlsoSeenIn),
			Time:       timeValue, TimeISO: nil,
			Metadata: metadata, Request: request, Response: response,
		}
		if timeValue != nil {
			item.TimeISO = timeISO(*timeValue)
		}
		if url == "" {
			url = raw.URL
		}
		if url != "" {
			item.URL = strPtr(url)
		}
		if host != "" {
			item.Host = strPtr(host)
		}
		if port != 0 {
			item.Port = intPtr(port)
		}
		if scheme != "" {
			item.Protocol = strPtr(scheme)
		}
		if method != "" {
			item.Method = strPtr(method)
		}
		if path != "" {
			item.Path = strPtr(path)
		}
		item.Status = status
		item.Comment = comment
		item.Highlight = metaStringPtr(raw.Meta, "highlight")
		if raw.RequestAddr != 0 {
			item.RequestFileOffset = int64Ptr(raw.RequestAddr)
		}
		if raw.ResponseAddr != 0 {
			item.ResponseFileOffset = int64Ptr(raw.ResponseAddr)
		}
		if len(warnings) > 0 {
			item.Warnings = warnings
		}
		out = append(out, item)
	}
	return out
}

func redactValue(value string) string {
	value = jwtRE.ReplaceAllString(value, "[REDACTED_JWT]")
	return secretKVRE.ReplaceAllString(value, "$1[REDACTED]")
}

func isSensitiveHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
		"x-auth-token", "x-csrf-token", "x-xsrf-token", "api-key", "x-access-token":
		return true
	}
	return false
}

func redactBodyFields(fields *BodyFields) {
	if fields == nil {
		return
	}
	for index := range fields.Headers {
		if isSensitiveHeader(fields.Headers[index][0]) {
			fields.Headers[index][1] = "[REDACTED]"
		} else {
			fields.Headers[index][1] = redactValue(fields.Headers[index][1])
		}
	}
	if fields.BodyEncoding != "base64" && fields.Body != "" {
		fields.Body = redactValue(fields.Body)
	}
}

func redactRequest(request *RequestMessage) {
	if request == nil {
		return
	}
	redactBodyFields(&request.BodyFields)
	for key := range request.Cookies {
		request.Cookies[key] = "[REDACTED]"
	}
	for _, params := range [][][2]any{request.QueryParams, request.BodyParams} {
		for index := range params {
			key := fmt.Sprint(params[index][0])
			if regexpSensitiveKey.MatchString(key) {
				params[index][1] = "[REDACTED]"
			}
		}
	}
	request.Target = redactValue(request.Target)
	request.RequestLine = redactValue(request.RequestLine)
}

func redactResponse(response *ResponseMessage) {
	if response == nil {
		return
	}
	redactBodyFields(&response.BodyFields)
}

func redactItems(items []Item) {
	for index := range items {
		redactRequest(items[index].Request)
		redactResponse(items[index].Response)
		if items[index].URL != nil {
			value := redactValue(*items[index].URL)
			items[index].URL = &value
		}
		if items[index].Comment != nil {
			value := redactValue(*items[index].Comment)
			items[index].Comment = &value
		}
		meta := items[index].Metadata
		if meta == nil {
			continue
		}
		if cookie := metaStringPtr(meta, "cookie_header"); cookie != nil && *cookie != "" {
			meta["cookie_header"] = "[REDACTED]"
		}
		if title := metaStringPtr(meta, "title"); title != nil {
			meta["title"] = redactValue(*title)
		}
	}
}

func redactCollaborator(collaborator *Collaborator) {
	for index := range collaborator.Interactions {
		redactRequest(collaborator.Interactions[index].Request)
		redactResponse(collaborator.Interactions[index].Response)
	}
}

func buildSummary(items []Item) *Summary {
	hosts := map[string]int{}
	hostDetails := map[string]*HostDetail{}
	endpoints := map[string]*Endpoint{}
	endpointOrder := []string{}
	statusCodes := map[string]int{}
	methods := map[string]int{}
	contentTypes := map[string]int{}
	technology := map[string]int{}
	cookies := map[string]bool{}
	authHeaders := map[string]bool{}
	paramNames := map[string]bool{}
	secMissing := map[string]int{}
	redirects := []RedirectInfo{}
	clientErrors := []ErrorInfo{}
	serverErrors := []ErrorInfo{}
	sourceTools := map[string]int{}
	highlights := map[string]int{}

	for _, item := range items {
		source := item.SourceTool
		if source == "" {
			source = "unknown"
		}
		sourceTools[source]++
		if item.Highlight != nil && *item.Highlight != "" {
			highlights[*item.Highlight]++
		}
		host := ""
		if item.Host != nil {
			host = *item.Host
		}
		if host != "" {
			hosts[host]++
			detail, ok := hostDetails[host]
			if !ok {
				detail = &HostDetail{Host: host, Ports: []int{}, Protocols: []string{}}
				hostDetails[host] = detail
			}
			detail.Count++
			if item.Port != nil && !containsInt(detail.Ports, *item.Port) {
				detail.Ports = append(detail.Ports, *item.Port)
			}
			if item.Protocol != nil && *item.Protocol != "" && !containsString(detail.Protocols, *item.Protocol) {
				detail.Protocols = append(detail.Protocols, *item.Protocol)
			}
		}
		request, response := item.Request, item.Response
		if request != nil {
			methods[request.Method]++
			key := host + "\x00" + request.Method + "\x00" + request.Path
			endpoint, ok := endpoints[key]
			if !ok {
				endpoint = &Endpoint{Host: host, Method: request.Method, Path: request.Path,
					Statuses: map[string]int{}, Params: []string{}}
				endpoints[key] = endpoint
				endpointOrder = append(endpointOrder, key)
			}
			endpoint.Count++
			for _, group := range [][][2]any{request.QueryParams, request.BodyParams} {
				for _, pair := range group {
					name := fmt.Sprint(pair[0])
					if !containsString(endpoint.Params, name) {
						endpoint.Params = append(endpoint.Params, name)
					}
					paramNames[name] = true
				}
			}
			for name := range request.Cookies {
				cookies[name] = true
			}
			for _, header := range request.Headers {
				switch strings.ToLower(header[0]) {
				case "authorization", "x-api-key", "x-auth-token", "x-csrf-token", "proxy-authorization":
					authHeaders[header[0]] = true
				}
			}
			if response != nil {
				endpoint.Statuses[strconv.Itoa(response.Status)]++
			}
		}
		if response != nil {
			status := strconv.Itoa(response.Status)
			statusCodes[status]++
			if response.ContentType != "" {
				contentTypes[response.ContentType]++
			}
			for _, name := range []string{"server", "x-powered-by", "x-aspnet-version", "via"} {
				if value := headerValue(response.Headers, name); value != "" {
					technology[fmt.Sprintf("%s: %s", name, value)]++
				}
			}
			headerNames := map[string]bool{}
			for _, header := range response.Headers {
				headerNames[strings.ToLower(header[0])] = true
			}
			if response.Status < 300 {
				for _, name := range []string{"strict-transport-security", "content-security-policy",
					"x-content-type-options", "x-frame-options"} {
					if !headerNames[name] {
						secMissing[name]++
					}
				}
			}
			location := headerValue(response.Headers, "location")
			if response.Status >= 300 && response.Status < 400 {
				info := RedirectInfo{ID: item.ID, URL: item.URL, Status: intPtr(response.Status)}
				if location != "" {
					info.Location = &location
				}
				redirects = append(redirects, info)
			}
			if response.Status >= 500 {
				serverErrors = append(serverErrors, ErrorInfo{ID: item.ID, URL: item.URL, Status: intPtr(response.Status)})
			} else if response.Status >= 400 {
				if len(clientErrors) < 100 {
					clientErrors = append(clientErrors, ErrorInfo{ID: item.ID, URL: item.URL, Status: intPtr(response.Status)})
				}
			}
		}
	}

	sort.Strings(endpointOrder)
	endpointList := make([]Endpoint, 0, len(endpoints))
	for _, key := range endpointOrder {
		endpoint := endpoints[key]
		sort.Strings(endpoint.Params)
		endpointList = append(endpointList, *endpoint)
	}
	sort.SliceStable(endpointList, func(i, j int) bool {
		if endpointList[i].Host != endpointList[j].Host {
			return endpointList[i].Host < endpointList[j].Host
		}
		return endpointList[i].Path < endpointList[j].Path
	})

	hostNames := make([]string, 0, len(hosts))
	for host := range hosts {
		hostNames = append(hostNames, host)
	}
	sort.Strings(hostNames)
	hostDetailList := make([]HostDetail, 0, len(hostNames))
	for _, host := range hostNames {
		detail := hostDetails[host]
		sort.Ints(detail.Ports)
		sort.Strings(detail.Protocols)
		hostDetailList = append(hostDetailList, *detail)
	}

	params := make([]string, 0, len(paramNames))
	for name := range paramNames {
		params = append(params, name)
	}
	sort.Strings(params)
	cookieList := keysOf(cookies)
	sort.Strings(cookieList)
	authList := keysOf(authHeaders)
	sort.Strings(authList)
	if len(serverErrors) > 50 {
		serverErrors = serverErrors[:50]
	}
	return &Summary{
		TotalItems: len(items), SourceToolCounts: sourceTools, Hosts: hosts,
		HostDetails: hostDetailList, Endpoints: endpointList, ParameterNames: params,
		Methods: methods, StatusCodes: statusCodes, ContentTypes: contentTypes,
		TechnologyHeaders: technology, CookieNamesSeen: cookieList,
		AuthHeaderNamesSeen: authList, ResponsesMissingSecurityHeaders: secMissing,
		Redirects: redirects, ClientErrors: clientErrors, ServerErrors: serverErrors,
		Highlights: highlights,
	}
}

func keysOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	return out
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
