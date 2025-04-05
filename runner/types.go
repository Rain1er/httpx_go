package runner

import (
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"time"
)

type AsnResponse struct {
	AsNumber  string   `json:"as_number" csv:"as_number"`
	AsName    string   `json:"as_name" csv:"as_name"`
	AsCountry string   `json:"as_country" csv:"as_country"`
	AsRange   []string `json:"as_range" csv:"as_range"`
}

// Result of a scan
type Result struct {
	Timestamp          time.Time                     `json:"timestamp,omitempty" csv:"timestamp" mapstructure:"timestamp"`
	ASN                *AsnResponse                  `json:"asn,omitempty" csv:"asn" mapstructure:"asn"`
	Err                error                         `json:"-" csv:"-" mapstructure:"-"`
	CSPData            *httpx.CSPData                `json:"csp,omitempty" csv:"csp" mapstructure:"csp"`
	TLSData            *clients.Response             `json:"tls,omitempty" csv:"tls" mapstructure:"tls"`
	Hashes             map[string]interface{}        `json:"hash,omitempty" csv:"hash" mapstructure:"hash"`
	ExtractRegex       []string                      `json:"extract_regex,omitempty" csv:"extract_regex" mapstructure:"extract_regex"`
	CDNName            string                        `json:"cdn_name,omitempty" csv:"cdn_name" mapstructure:"cdn_name"`
	CDNType            string                        `json:"cdn_type,omitempty" csv:"cdn_type" mapstructure:"cdn_type"`
	SNI                string                        `json:"sni,omitempty" csv:"sni" mapstructure:"sni"`
	Port               string                        `json:"port,omitempty" csv:"port" mapstructure:"port"`
	Raw                string                        `json:"-" csv:"-" mapstructure:"-"`
	URL                string                        `json:"url,omitempty" csv:"url" mapstructure:"url"`
	Input              string                        `json:"input,omitempty" csv:"input" mapstructure:"input"`
	Location           string                        `json:"location,omitempty" csv:"location" mapstructure:"location"`
	Title              string                        `json:"title,omitempty" csv:"title" mapstructure:"title"`
	str                string                        `mapstructure:"-"`
	Scheme             string                        `json:"scheme,omitempty" csv:"scheme" mapstructure:"scheme"`
	Error              string                        `json:"error,omitempty" csv:"error" mapstructure:"error"`
	WebServer          string                        `json:"webserver,omitempty" csv:"webserver" mapstructure:"webserver"`
	ResponseBody       string                        `json:"body,omitempty" csv:"-" mapstructure:"body"`
	BodyPreview        string                        `json:"body_preview,omitempty" csv:"body_preview" mapstructure:"body_preview"`
	ContentType        string                        `json:"content_type,omitempty" csv:"content_type" mapstructure:"content_type"`
	Method             string                        `json:"method,omitempty" csv:"method" mapstructure:"method"`
	Host               string                        `json:"host,omitempty" csv:"host" mapstructure:"host"`
	Path               string                        `json:"path,omitempty" csv:"path" mapstructure:"path"`
	FavIconMMH3        string                        `json:"favicon,omitempty" csv:"favicon" mapstructure:"favicon"`
	FavIconMD5         string                        `json:"favicon_md5,omitempty" csv:"favicon_md5" mapstructure:"favicon_md5"`
	FaviconPath        string                        `json:"favicon_path,omitempty" csv:"favicon_path" mapstructure:"favicon_path"`
	FaviconURL         string                        `json:"favicon_url,omitempty" csv:"favicon_url" mapstructure:"favicon_url"`
	FinalURL           string                        `json:"final_url,omitempty" csv:"final_url" mapstructure:"final_url"`
	ResponseHeaders    map[string]interface{}        `json:"header,omitempty" csv:"-" mapstructure:"header"`
	RawHeaders         string                        `json:"raw_header,omitempty" csv:"-" mapstructure:"raw_header"`
	Request            string                        `json:"request,omitempty" csv:"-" mapstructure:"request"`
	ResponseTime       string                        `json:"time,omitempty" csv:"time" mapstructure:"time"`
	JarmHash           string                        `json:"jarm_hash,omitempty" csv:"jarm_hash" mapstructure:"jarm_hash"`
	ChainStatusCodes   []int                         `json:"chain_status_codes,omitempty" csv:"chain_status_codes" mapstructure:"chain_status_codes"`
	A                  []string                      `json:"a,omitempty" csv:"a" mapstructure:"a"`
	AAAA               []string                      `json:"aaaa,omitempty" csv:"aaaa" mapstructure:"aaaa"`
	CNAMEs             []string                      `json:"cname,omitempty" csv:"cname" mapstructure:"cname"`
	Technologies       []string                      `json:"tech,omitempty" csv:"tech" mapstructure:"tech"`
	Extracts           map[string][]string           `json:"extracts,omitempty" csv:"extracts" mapstructure:"extracts"`
	Chain              []httpx.ChainItem             `json:"chain,omitempty" csv:"chain" mapstructure:"chain"`
	Words              int                           `json:"words" csv:"words" mapstructure:"words"`
	Lines              int                           `json:"lines" csv:"lines" mapstructure:"lines"`
	StatusCode         int                           `json:"status_code" csv:"status_code" mapstructure:"status_code"`
	ContentLength      int                           `json:"content_length" csv:"content_length" mapstructure:"content_length"`
	Failed             bool                          `json:"failed" csv:"failed" mapstructure:"failed"`
	VHost              bool                          `json:"vhost,omitempty" csv:"vhost" mapstructure:"vhost"`
	WebSocket          bool                          `json:"websocket,omitempty" csv:"websocket" mapstructure:"websocket"`
	CDN                bool                          `json:"cdn,omitempty" csv:"cdn" mapstructure:"cdn"`
	HTTP2              bool                          `json:"http2,omitempty" csv:"http2" mapstructure:"http2"`
	Pipeline           bool                          `json:"pipeline,omitempty" csv:"pipeline" mapstructure:"pipeline"`
	HeadlessBody       string                        `json:"headless_body,omitempty" csv:"headless_body" mapstructure:"headless_body"`
	ScreenshotBytes    []byte                        `json:"screenshot_bytes,omitempty" csv:"screenshot_bytes" mapstructure:"screenshot_bytes"`
	StoredResponsePath string                        `json:"stored_response_path,omitempty" csv:"stored_response_path" mapstructure:"stored_response_path"`
	ScreenshotPath     string                        `json:"screenshot_path,omitempty" csv:"screenshot_path" mapstructure:"screenshot_path"`
	ScreenshotPathRel  string                        `json:"screenshot_path_rel,omitempty" csv:"screenshot_path_rel" mapstructure:"screenshot_path_rel"`
	KnowledgeBase      map[string]interface{}        `json:"knowledgebase,omitempty" csv:"knowledgebase" mapstructure:"knowledgebase"`
	Resolvers          []string                      `json:"resolvers,omitempty" csv:"resolvers" mapstructure:"resolvers"`
	Fqdns              []string                      `json:"body_fqdn,omitempty" mapstructure:"body_fqdn"`
	Domains            []string                      `json:"body_domains,omitempty" mapstructure:"body_domains"`
	TechnologyDetails  map[string]wappalyzer.AppInfo `json:"-" csv:"-" mapstructure:"-"`
	RequestRaw         []byte                        `json:"-" csv:"-" mapstructure:"-"`
	Response           *httpx.Response               `json:"-" csv:"-" mapstructure:"-"`
	FaviconData        []byte                        `json:"-" csv:"-" mapstructure:"-"`
	Trace              *retryablehttp.TraceInfo      `json:"trace,omitempty" csv:"trace"  mapstructure:"trace"`
}
