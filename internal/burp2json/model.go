package burp2json

// Shared data model used by the parsers and the compact output builder.

type Header = [2]string

type BodyFields struct {
	Headers       [][2]string
	ContentType   string
	Body          string
	BodyEncoding  string
	BodyLength    int
	BodyTruncated bool
}

type RequestMessage struct {
	Method      string
	Target      string
	HTTPVersion string
	RequestLine string
	BodyFields
	Path        string
	QueryParams [][2]any
	Cookies     map[string]string
	BodyParams  [][2]any
	HostHeader  string
}

type ResponseMessage struct {
	Status      int
	Reason      string
	HTTPVersion string
	StatusLine  string
	BodyFields
}

type Service struct {
	Host                   string
	Port                   *int
	TLS                    *bool
	RequestMetadataAddress int64
	ServiceAddress         int64
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
	ID                 int
	SourceTool         string
	AlsoSeenIn         []string
	Time               *int64
	TimeISO            *string
	URL                *string
	Host               *string
	Port               *int
	Protocol           *string
	Method             *string
	Path               *string
	Status             *int
	Comment            *string
	Highlight          *string
	Metadata           map[string]any
	Request            *RequestMessage
	Response           *ResponseMessage
	RequestFileOffset  *int64
	ResponseFileOffset *int64
	Warnings           []string
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
	Type            string
	Host            string
	Method          string
	Path            string
	RequestLine     string
	ResponseStatus  *int
	ResponseServer  *string
	RequestAddress  int64
	ResponseAddress *int64
	Request         *RequestMessage
	Response        *ResponseMessage
}

type Collaborator struct {
	DomainsSeen          []string
	InteractionTypesSeen []string
	Interactions         []Interaction
	Note                 string
}

type BurpInfo struct {
	Magic           string
	OuterVersion    int
	Compatibility   string
	SchemaFloor     int
	SchemaCurrent   int
	ProjectName     *string
	BurpVersion     *string
	BurpVersionNote string
}

type Meta struct {
	Tool             string
	ToolVersion      string
	SourceFile       string
	SourceSHA256     string
	SourceSize       int64
	InputFormat      string
	ExtractionMethod string
	GeneratedAt      string
	ReadOnly         bool
	ItemCount        int
	SourceToolCounts map[string]int
	Redacted         bool
	Burp             *BurpInfo
	Warnings         []string
	Part             int
	Parts            int
}

type HostDetail struct {
	Host      string
	Count     int
	Ports     []int
	Protocols []string
}

type Endpoint struct {
	Host     string
	Method   string
	Path     string
	Count    int
	Statuses map[string]int
	Params   []string
}

type RedirectInfo struct {
	ID       int
	URL      *string
	Status   *int
	Location *string
}

type ErrorInfo struct {
	ID     int
	URL    *string
	Status *int
}

type Summary struct {
	TotalItems                      int
	SourceToolCounts                map[string]int
	Hosts                           map[string]int
	HostDetails                     []HostDetail
	Endpoints                       []Endpoint
	ParameterNames                  []string
	Methods                         map[string]int
	StatusCodes                     map[string]int
	ContentTypes                    map[string]int
	TechnologyHeaders               map[string]int
	CookieNamesSeen                 []string
	AuthHeaderNamesSeen             []string
	ResponsesMissingSecurityHeaders map[string]int
	Redirects                       []RedirectInfo
	ClientErrors                    []ErrorInfo
	ServerErrors                    []ErrorInfo
	Highlights                      map[string]int
}

// Result is the internal aggregate consumed by the compact output builder.
// It is never serialized directly; the output schema lives in compact.go.
type Result struct {
	Meta         Meta
	Summary      *Summary
	Collaborator Collaborator
	Repeater     RepeaterInfo
	Coverage     map[string]any
	Items        []Item
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
