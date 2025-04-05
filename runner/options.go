package runner

import (
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/customheader"
	"github.com/projectdiscovery/httpx/common/customlist"
	customport "github.com/projectdiscovery/httpx/common/customports"
	"github.com/projectdiscovery/networkpolicy"
	fileutil "github.com/projectdiscovery/utils/file"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"regexp"
	"time"
)

// OnResultCallback (hostResult)
type OnResultCallback func(Result)

type ScanOptions struct {
	Methods                   []string
	StoreResponseDirectory    string
	RequestURI                string
	RequestBody               string
	VHost                     bool
	OutputTitle               bool
	OutputStatusCode          bool
	OutputLocation            bool
	OutputContentLength       bool
	StoreResponse             bool
	OmitBody                  bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	OutputWithNoColor         bool
	OutputMethod              bool
	ResponseHeadersInStdout   bool
	ResponseInStdout          bool
	Base64ResponseInStdout    bool
	ChainInStdout             bool
	TLSProbe                  bool
	CSPProbe                  bool
	VHostInput                bool
	OutputContentType         bool
	Unsafe                    bool
	Pipeline                  bool
	HTTP2Probe                bool
	OutputIP                  bool
	OutputCName               bool
	OutputCDN                 string
	OutputResponseTime        bool
	PreferHTTPS               bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                bool
	StoreChain                bool
	StoreVisionReconClusters  bool
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	OutputExtractRegex        string
	extractRegexps            map[string]*regexp.Regexp
	ExcludeCDN                bool
	HostMaxErrors             int
	ProbeAllIPS               bool
	Favicon                   bool
	LeaveDefaultPorts         bool
	OutputLinesCount          bool
	OutputWordsCount          bool
	Hashes                    string
	Screenshot                bool
	UseInstalledChrome        bool
	DisableStdin              bool
	NoScreenshotBytes         bool
	NoHeadlessBody            bool
	ScreenshotTimeout         time.Duration
	ScreenshotIdle            time.Duration
}

// Options contains configuration options for httpx.
type Options struct {
	CustomHeaders       customheader.CustomHeaders
	CustomPorts         customport.CustomPorts
	matchStatusCode     []int
	matchContentLength  []int
	filterStatusCode    []int
	filterContentLength []int
	Output              string
	OutputAll           bool
	StoreResponseDir    string
	OmitBody            bool
	// Deprecated: use Proxy
	HTTPProxy string
	// Deprecated: use Proxy
	SocksProxy                string
	Proxy                     string
	InputFile                 string
	InputTargetHost           goflags.StringSlice
	Methods                   string
	RequestURI                string
	RequestURIs               string
	requestURIs               []string
	OutputMatchStatusCode     string
	OutputMatchContentLength  string
	OutputFilterStatusCode    string
	OutputFilterErrorPage     bool
	FilterOutDuplicates       bool
	OutputFilterContentLength string
	InputRawRequest           string
	rawRequest                string
	RequestBody               string
	OutputFilterString        goflags.StringSlice
	OutputMatchString         goflags.StringSlice
	OutputFilterRegex         goflags.StringSlice
	OutputMatchRegex          goflags.StringSlice
	Retries                   int
	Threads                   int
	Timeout                   int
	Delay                     time.Duration
	filterRegexes             []*regexp.Regexp
	matchRegexes              []*regexp.Regexp
	VHost                     bool
	VHostInput                bool
	Smuggling                 bool
	ExtractTitle              bool
	StatusCode                bool
	Location                  bool
	ContentLength             bool
	FollowRedirects           bool
	RespectHSTS               bool
	StoreResponse             bool
	JSONOutput                bool
	CSVOutput                 bool
	CSVOutputEncoding         string
	PdcpAuth                  string
	PdcpAuthCredFile          string
	Silent                    bool
	Version                   bool
	Verbose                   bool
	NoColor                   bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	ResponseHeadersInStdout   bool
	ResponseInStdout          bool
	Base64ResponseInStdout    bool
	ChainInStdout             bool
	FollowHostRedirects       bool
	MaxRedirects              int
	OutputMethod              bool
	TLSProbe                  bool
	CSPProbe                  bool
	OutputContentType         bool
	OutputIP                  bool
	OutputCName               bool
	ExtractFqdn               bool
	Unsafe                    bool
	Debug                     bool
	DebugRequests             bool
	DebugResponse             bool
	Pipeline                  bool
	HTTP2Probe                bool
	OutputCDN                 string
	OutputResponseTime        bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                bool
	TLSGrab                   bool
	protocol                  string
	ShowStatistics            bool
	StatsInterval             int
	RandomAgent               bool
	StoreChain                bool
	StoreVisionReconClusters  bool
	Deny                      customlist.CustomList
	Allow                     customlist.CustomList
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	ResponseBodyPreviewSize   int
	OutputExtractRegexs       goflags.StringSlice
	OutputExtractPresets      goflags.StringSlice
	RateLimit                 int
	RateLimitMinute           int
	Probe                     bool
	Resume                    bool
	resumeCfg                 *ResumeCfg
	Exclude                   goflags.StringSlice
	HostMaxErrors             int
	Stream                    bool
	SkipDedupe                bool
	ProbeAllIPS               bool
	Resolvers                 goflags.StringSlice
	Favicon                   bool
	OutputFilterFavicon       goflags.StringSlice
	OutputMatchFavicon        goflags.StringSlice
	LeaveDefaultPorts         bool
	ZTLS                      bool
	OutputLinesCount          bool
	OutputMatchLinesCount     string
	matchLinesCount           []int
	OutputFilterLinesCount    string
	Memprofile                string
	filterLinesCount          []int
	OutputWordsCount          bool
	OutputMatchWordsCount     string
	matchWordsCount           []int
	OutputFilterWordsCount    string
	filterWordsCount          []int
	Hashes                    string
	Jarm                      bool
	Asn                       bool
	OutputMatchCdn            goflags.StringSlice
	OutputFilterCdn           goflags.StringSlice
	SniName                   string
	OutputMatchResponseTime   string
	OutputFilterResponseTime  string
	HealthCheck               bool
	ListDSLVariable           bool
	OutputFilterCondition     string
	OutputMatchCondition      string
	StripFilter               string
	//The OnResult callback function is invoked for each result. It is important to check for errors in the result before using Result.Err.
	OnResult           OnResultCallback
	DisableUpdateCheck bool
	NoDecode           bool
	Screenshot         bool
	UseInstalledChrome bool
	TlsImpersonate     bool
	DisableStdin       bool
	HttpApiEndpoint    string
	NoScreenshotBytes  bool
	NoHeadlessBody     bool
	ScreenshotTimeout  time.Duration
	ScreenshotIdle     time.Duration
	// HeadlessOptionalArguments specifies optional arguments to pass to Chrome
	HeadlessOptionalArguments goflags.StringSlice
	Protocol                  string
	OutputFilterErrorPagePath string
	DisableStdout             bool
	// AssetUpload
	AssetUpload bool
	// AssetName
	AssetName string
	// AssetID
	AssetID string
	// AssetFileUpload
	AssetFileUpload string
	TeamID          string
	// OnClose adds a callback function that is invoked when httpx is closed
	// to be exact at end of existing closures
	OnClose func()

	Trace bool

	// Optional pre-created objects to reduce allocations
	Wappalyzer     *wappalyzer.Wappalyze
	Networkpolicy  *networkpolicy.NetworkPolicy
	CDNCheckClient *cdncheck.Client
}

// ParseOptions 解析命令行选项并初始化配置。
// 该函数使用goflags来定义和解析命令行参数，专注于输入参数如目标列表文件、原始请求文件等。
// 返回值是一个指向Options结构的指针，它包含了从命令行参数中解析出的配置信息。
func ParseOptions() *Options {
	// 初始化Options实例。
	options := &Options{}
	// 中断后继续扫描的标识
	var cfgFile string

	// 创建一个新的FlagSet实例，用于解析命令行参数。
	flagSet := goflags.NewFlagSet()
	// 设置工具的描述信息。
	flagSet.SetDescription(`httpx is a fast and multi-purpose HTTP toolkit made for both manual and automatedpentesting.`)

	// 创建并定义输入参数组，包括目标列表文件、原始请求文件和目标主机。
	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&options.InputFile, "list", "l", "", "Input file containing list of targets"),
		flagSet.StringVarP(&options.InputRawRequest, "request", "rr", "", "file containing raw request"),
		// 允许用户通过命令行传递多个值（以逗号分隔），并将这些值存储到指定的变量中。
		flagSet.StringSliceVarP(&options.InputTargetHost, "target", "u", nil, "input target hosts(s) to probe", goflags.CommaSeparatedStringSliceOptions),
	)
	_ = flagSet.Parse()

	if cfgFile != "" {
		if !fileutil.FileExists(cfgFile) {
			gologger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}

		// merge config file with flags
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("could not read config: %s\n", err)
		}
	}
	showBanner()
	return options
}
