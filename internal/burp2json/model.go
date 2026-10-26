package burp2json

// Shared data model. JSON field names are kept stable for existing consumers.

type Header = [2]string

type BodyFields struct {
	Headers       [][2]string `json:"headers"`
	ContentType   string      `json:"content_type,omitempty"`
	Body          string      `json:"body"`
	BodyEncoding  string      `json:"body_encoding"`
	BodyLength    int         `json:"body_length"`
	BodyTruncated bool        `json:"body_truncated"`
}

type RequestMessage struct {
	Method      string `json:"method"`
	Target      string `json:"target"`
	HTTPVersion string `json:"http_version,omitempty"`
	RequestLine string `json:"request_line"`
	BodyFields
	Path        string            `json:"path"`
	QueryParams [][2]any          `json:"query_params"`
	Cookies     map[string]string `json:"cookies"`
	BodyParams  [][2]any          `json:"body_params"`
	HostHeader  string            `json:"host_header,omitempty"`
}

type ResponseMessage struct {
	Status      int    `json:"status"`
	Reason      string `json:"reason,omitempty"`
	HTTPVersion string `json:"http_version,omitempty"`
	StatusLine  string `json:"status_line"`
	BodyFields
}

type Service struct {
	Host                   string `json:"host"`
	Port                   *int   `json:"port"`
	TLS                    *bool  `json:"tls"`
	RequestMetadataAddress int64  `json:"request_metadata_address"`
	ServiceAddress         int64  `json:"service_address"`
}

type Exchange struct {
	Source       string
	RequestAddr  int64
	ResponseAddr int64
	RequestRaw   []byte
	ResponseRaw  []byte
	Meta         map[string]any
	Request      *RequestMessage
	Response     *ResponseMessage
	Warnings     []string
	AlsoSeenIn   []string
	URL          string
	Host         string
	Protocol     string
	Port         int
	Method       string
	Path         string
	Status       *int
	Comment      *string
	Time         *int64
}

type Item struct {
	ID                 int              `json:"id"`
	SourceTool         string           `json:"source_tool"`
	AlsoSeenIn         []string         `json:"also_seen_in"`
	Time               *int64           `json:"time"`
	TimeISO            *string          `json:"time_iso"`
	URL                *string          `json:"url"`
	Host               *string          `json:"host"`
	Port               *int             `json:"port"`
	Protocol           *string          `json:"protocol"`
	Method             *string          `json:"method"`
	Path               *string          `json:"path"`
	Status             *int             `json:"status"`
	Comment            *string          `json:"comment"`
	Highlight          *string          `json:"highlight"`
	Metadata           map[string]any   `json:"metadata"`
	Request            *RequestMessage  `json:"request"`
	Response           *ResponseMessage `json:"response"`
	RequestFileOffset  *int64           `json:"request_file_offset,omitempty"`
	ResponseFileOffset *int64           `json:"response_file_offset,omitempty"`
	Warnings           []string         `json:"warnings,omitempty"`
}

type Group struct {
	Address  int64   `json:"address"`
	Name     *string `json:"name"`
	Color    *int    `json:"color"`
	Expanded *bool   `json:"expanded"`
	Index    *int    `json:"index"`
	UUID     *string `json:"uuid"`
}

type Tab struct {
	Address   int64   `json:"address"`
	Caption   *string `json:"caption"`
	UUID      *string `json:"uuid"`
	Group     *Group  `json:"group"`
	PairCount int     `json:"pair_count"`
}

type RepeaterInfo struct {
	Tabs   []Tab   `json:"tabs"`
	Groups []Group `json:"groups"`
}

type Interaction struct {
	Type            string           `json:"type"`
	Host            string           `json:"host"`
	Method          string           `json:"method"`
	Path            string           `json:"path"`
	RequestLine     string           `json:"request_line"`
	ResponseStatus  *int             `json:"response_status"`
	ResponseServer  *string          `json:"response_server"`
	RequestAddress  int64            `json:"request_address"`
	ResponseAddress *int64           `json:"response_address"`
	Request         *RequestMessage  `json:"request"`
	Response        *ResponseMessage `json:"response"`
}

type Collaborator struct {
	DomainsSeen          []string      `json:"domains_seen"`
	InteractionTypesSeen []string      `json:"interaction_types_seen"`
	Interactions         []Interaction `json:"interactions"`
	Note                 string        `json:"note"`
}

type BurpInfo struct {
	Magic           string  `json:"magic"`
	OuterVersion    int     `json:"outer_version"`
	Compatibility   string  `json:"compatibility"`
	SchemaFloor     int     `json:"schema_floor"`
	SchemaCurrent   int     `json:"schema_current"`
	ProjectName     *string `json:"project_name"`
	BurpVersion     *string `json:"burp_version"`
	BurpVersionNote string  `json:"burp_version_note"`
}

type Meta struct {
	Tool             string         `json:"tool"`
	ToolVersion      string         `json:"tool_version"`
	SourceFile       string         `json:"source_file"`
	SourceSHA256     string         `json:"source_sha256"`
	SourceSize       int64          `json:"source_size"`
	InputFormat      string         `json:"input_format"`
	ExtractionMethod string         `json:"extraction_method"`
	GeneratedAt      string         `json:"generated_at"`
	ReadOnly         bool           `json:"read_only"`
	ItemCount        int            `json:"item_count"`
	SourceToolCounts map[string]int `json:"source_tool_counts"`
	Redacted         bool           `json:"redacted"`
	Burp             *BurpInfo      `json:"burp"`
	Warnings         []string       `json:"warnings"`
	Part             int            `json:"part,omitempty"`
	Parts            int            `json:"parts,omitempty"`
}

type HostDetail struct {
	Host      string   `json:"host"`
	Count     int      `json:"count"`
	Ports     []int    `json:"ports"`
	Protocols []string `json:"protocols"`
}

type Endpoint struct {
	Host     string         `json:"host"`
	Method   string         `json:"method"`
	Path     string         `json:"path"`
	Count    int            `json:"count"`
	Statuses map[string]int `json:"statuses"`
	Params   []string       `json:"params"`
}

type RedirectInfo struct {
	ID       int     `json:"id"`
	URL      *string `json:"url"`
	Status   *int    `json:"status"`
	Location *string `json:"location"`
}

type ErrorInfo struct {
	ID     int     `json:"id"`
	URL    *string `json:"url"`
	Status *int    `json:"status"`
}

type Summary struct {
	TotalItems                      int            `json:"total_items"`
	SourceToolCounts                map[string]int `json:"source_tool_counts"`
	Hosts                           map[string]int `json:"hosts"`
	HostDetails                     []HostDetail   `json:"host_details"`
	Endpoints                       []Endpoint     `json:"endpoints"`
	ParameterNames                  []string       `json:"parameter_names"`
	Methods                         map[string]int `json:"methods"`
	StatusCodes                     map[string]int `json:"status_codes"`
	ContentTypes                    map[string]int `json:"content_types"`
	TechnologyHeaders               map[string]int `json:"technology_headers"`
	CookieNamesSeen                 []string       `json:"cookie_names_seen"`
	AuthHeaderNamesSeen             []string       `json:"auth_header_names_seen"`
	ResponsesMissingSecurityHeaders map[string]int `json:"responses_missing_security_headers"`
	Redirects                       []RedirectInfo `json:"redirects"`
	ClientErrors                    []ErrorInfo    `json:"client_errors"`
	ServerErrors                    []ErrorInfo    `json:"server_errors"`
	Highlights                      map[string]int `json:"highlights"`
}

type Document struct {
	AIInstructions string         `json:"ai_instructions"`
	Meta           Meta           `json:"meta"`
	Summary        *Summary       `json:"summary,omitempty"`
	Collaborator   Collaborator   `json:"collaborator"`
	Repeater       RepeaterInfo   `json:"repeater"`
	Intruder       map[string]any `json:"intruder"`
	Scanner        map[string]any `json:"scanner"`
	Coverage       map[string]any `json:"coverage"`
	Items          []Item         `json:"items"`
}

type ExtractionResult struct {
	Items        []*Exchange
	Collaborator Collaborator
	Repeater     RepeaterInfo
	Coverage     map[string]any
	ProjectName  *string
	Header       *BurpHeader
}

func strPtr(v string) *string { return &v }
func intPtr(v int) *int       { return &v }
func int64Ptr(v int64) *int64 { return &v }
func boolPtr(v bool) *bool    { return &v }

func emptyRepeater() RepeaterInfo {
	return RepeaterInfo{Tabs: []Tab{}, Groups: []Group{}}
}

func emptyCollaborator(note string) Collaborator {
	return Collaborator{
		DomainsSeen:          []string{},
		InteractionTypesSeen: []string{},
		Interactions:         []Interaction{},
		Note:                 note,
	}
}
