package burp2json

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type xmlText struct {
	Base64 string `xml:"base64,attr"`
	Value  string `xml:",chardata"`
}

type xmlHost struct {
	IP    string `xml:"ip,attr"`
	Value string `xml:",chardata"`
}

type xmlItem struct {
	Time     string  `xml:"time"`
	URL      string  `xml:"url"`
	Host     xmlHost `xml:"host"`
	Port     string  `xml:"port"`
	Protocol string  `xml:"protocol"`
	Method   string  `xml:"method"`
	Path     string  `xml:"path"`
	Request  xmlText `xml:"request"`
	Response xmlText `xml:"response"`
	Comment  string  `xml:"comment"`
	Status   string  `xml:"status"`
	Type     string  `xml:"type"`
	TypeAttr string  `xml:"type,attr"`
}

type xmlItems struct {
	Items []xmlItem `xml:"item"`
}

func xmlRaw(element xmlText) []byte {
	if element.Value == "" {
		return nil
	}
	if element.Base64 == "true" {
		cleaned := strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, element.Value)
		data, err := base64.StdEncoding.DecodeString(cleaned)
		if err == nil {
			return data
		}
	}
	return []byte(element.Value)
}

func parseTimeValue(value string) *int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if number, err := strconv.ParseInt(value, 10, 64); err == nil {
		return &number
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			ms := parsed.UnixMilli()
			return &ms
		}
	}
	return nil
}

func readXML(path string, maxBody int, warnings *[]string) ([]*Exchange, string) {
	data, err := readInputFile(path, nil)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("could not read XML: %s", err))
		return []*Exchange{}, "burp-xml"
	}
	return readXMLData(data, maxBody, warnings, nil)
}

func readXMLData(data []byte, maxBody int, warnings *[]string, progress *progressBar) ([]*Exchange, string) {
	progress.Update("Parsing XML export", 20)
	var document xmlItems
	if err := xml.Unmarshal(data, &document); err != nil {
		*warnings = append(*warnings, fmt.Sprintf("could not parse XML: %s", err))
		progress.Update("XML export parsed", 88)
		return []*Exchange{}, "burp-xml"
	}
	progress.Update("Parsing XML export", 30)
	items := []*Exchange{}
	for itemIndex, item := range document.Items {
		if len(document.Items) > 0 {
			progress.Update("Parsing XML export", 30+58*float64(itemIndex+1)/float64(len(document.Items)))
		}
		requestRaw := xmlRaw(item.Request)
		responseRaw := xmlRaw(item.Response)
		source := strings.TrimSpace(item.Type)
		if source == "" {
			source = strings.TrimSpace(item.TypeAttr)
		}
		if source == "" {
			source = "xml-export"
		}
		exchange := &Exchange{
			Source: source, URL: item.URL, Host: strings.TrimSpace(item.Host.Value),
			Protocol: strings.TrimSpace(item.Protocol), Meta: map[string]any{},
			Time: parseTimeValue(item.Time),
		}
		if item.Host.IP != "" {
			exchange.Meta["ip"] = item.Host.IP
		}
		if port, err := strconv.Atoi(strings.TrimSpace(item.Port)); err == nil {
			exchange.Port = port
		}
		if comment := strings.TrimSpace(item.Comment); comment != "" {
			exchange.Comment = &comment
		}
		if len(requestRaw) > 0 {
			if parsed, ok := parseHTTP(requestRaw, true, maxBody, intPtr(len(requestRaw))); ok {
				exchange.Request = parsed.Request
				exchange.Warnings = append(exchange.Warnings, parsed.Warnings...)
			}
		}
		if len(responseRaw) > 0 {
			if parsed, ok := parseHTTP(responseRaw, false, maxBody, intPtr(len(responseRaw))); ok {
				exchange.Response = parsed.Response
				exchange.Warnings = append(exchange.Warnings, parsed.Warnings...)
			}
		}
		if exchange.Request == nil && exchange.Response == nil {
			*warnings = append(*warnings, "XML item has no parseable request or response")
			continue
		}
		items = append(items, exchange)
	}
	progress.Update("XML export parsed", 88)
	return items, "burp-xml"
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harContent struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding"`
}

type harRequest struct {
	Method      string       `json:"method"`
	URL         string       `json:"url"`
	HTTPVersion string       `json:"httpVersion"`
	Headers     []harHeader  `json:"headers"`
	PostData    *harPostData `json:"postData"`
}

type harResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	Content     *harContent `json:"content"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Comment         string      `json:"comment"`
}

type harDocument struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

func convertHARHeaders(headers []harHeader) [][2]string {
	out := make([][2]string, 0, len(headers))
	for _, header := range headers {
		out = append(out, [2]string{header.Name, header.Value})
	}
	return out
}

func readHARBytes(raw []byte, maxBody int, progress *progressBar) []*Exchange {
	progress.Update("Parsing HAR", 20)
	var document harDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil
	}
	progress.Update("Parsing HAR", 30)
	items := []*Exchange{}
	for entryIndex, entry := range document.Log.Entries {
		if len(document.Log.Entries) > 0 {
			progress.Update("Parsing HAR", 30+58*float64(entryIndex+1)/float64(len(document.Log.Entries)))
		}
		requestBody := encodeBody(nil, maxBody)
		if entry.Request.PostData != nil {
			requestBody = encodeBody([]byte(entry.Request.PostData.Text), maxBody)
			if entry.Request.PostData.MimeType != "" {
				requestBody.ContentType = strings.ToLower(strings.TrimSpace(
					strings.Split(entry.Request.PostData.MimeType, ";")[0]))
			}
		}
		requestBody.Headers = convertHARHeaders(entry.Request.Headers)
		request := &RequestMessage{
			Method: entry.Request.Method, Target: entry.Request.URL,
			HTTPVersion: entry.Request.HTTPVersion,
			RequestLine: fmt.Sprintf("%s %s %s", entry.Request.Method, entry.Request.URL, entry.Request.HTTPVersion),
			BodyFields:  requestBody,
			QueryParams: [][2]any{}, Cookies: map[string]string{}, BodyParams: [][2]any{},
		}

		var response *ResponseMessage
		if entry.Response.Status != 0 || entry.Response.StatusText != "" {
			body := []byte{}
			if entry.Response.Content != nil {
				if entry.Response.Content.Encoding == "base64" {
					if decoded, err := base64.StdEncoding.DecodeString(entry.Response.Content.Text); err == nil {
						body = decoded
					}
				} else {
					body = []byte(entry.Response.Content.Text)
				}
			}
			responseBody := encodeBody(body, maxBody)
			if entry.Response.Content != nil && entry.Response.Content.MimeType != "" {
				responseBody.ContentType = strings.ToLower(strings.TrimSpace(
					strings.Split(entry.Response.Content.MimeType, ";")[0]))
			}
			responseBody.Headers = convertHARHeaders(entry.Response.Headers)
			response = &ResponseMessage{
				Status: entry.Response.Status, Reason: entry.Response.StatusText,
				HTTPVersion: entry.Response.HTTPVersion,
				StatusLine: fmt.Sprintf("%s %d %s", entry.Response.HTTPVersion,
					entry.Response.Status, entry.Response.StatusText),
				BodyFields: responseBody,
			}
		}
		exchange := &Exchange{
			Source: "har", URL: entry.Request.URL, Host: "",
			Request: request, Response: response, Meta: map[string]any{},
			Time: parseTimeValue(entry.StartedDateTime),
		}
		if entry.Comment != "" {
			comment := entry.Comment
			exchange.Comment = &comment
		}
		items = append(items, exchange)
	}
	return items
}

func readHARData(data []byte, maxBody int, warnings *[]string, progress *progressBar) ([]*Exchange, string) {
	items := readHARBytes(data, maxBody, progress)
	if items == nil {
		*warnings = append(*warnings, "could not parse HAR JSON")
		items = []*Exchange{}
	}
	progress.Update("HAR parsed", 88)
	return items, "har"
}

func readHAR(path string, maxBody int, warnings *[]string) ([]*Exchange, string) {
	data, err := readInputFile(path, nil)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("could not read HAR: %s", err))
		return []*Exchange{}, "har"
	}
	return readHARData(data, maxBody, warnings, nil)
}
