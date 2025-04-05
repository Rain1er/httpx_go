package runner

import (
	"github.com/Mzack9999/gcache"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/common/pagetypeclassifier"
	"github.com/projectdiscovery/ratelimit"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"os"
	"path/filepath"
)

type pHashCluster struct {
	BasePHash uint64     `json:"base_phash,omitempty" csv:"base_phash"`
	Hashes    []pHashUrl `json:"hashes,omitempty" csv:"hashes"`
}
type pHashUrl struct {
	PHash uint64 `json:"phash,omitempty" csv:"phash"`
	Url   string `json:"url,omitempty" csv:"url"`
}

// Runner is a client for running the enumeration process.
type Runner struct {
	options            *Options
	hp                 *httpx.HTTPX
	wappalyzer         *wappalyzer.Wappalyze
	scanopts           ScanOptions
	hm                 *hybrid.HybridMap
	excludeCdn         bool
	stats              clistats.StatisticsClient
	ratelimiter        ratelimit.Limiter
	HostErrorsCache    gcache.Cache[string, int]
	browser            *Browser
	pageTypeClassifier *pagetypeclassifier.PageTypeClassifier // Include this for general page classification
	pHashClusters      []pHashCluster
	simHashes          gcache.Cache[uint64, struct{}] // Include simHashes for efficient duplicate detection
	//httpApiEndpoint    *Server
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	var err error
	if options.Wappalyzer != nil {
		runner.wappalyzer = options.Wappalyzer
	} else if options.TechDetect || options.JSONOutput || options.CSVOutput || options.AssetUpload {
		runner.wappalyzer, err = wappalyzer.New()
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not create wappalyzer client")
	}

	if options.StoreResponseDir != "" {
		_ = os.RemoveAll(filepath.Join(options.StoreResponseDir, "response", "index.txt"))
		_ = os.RemoveAll(filepath.Join(options.StoreResponseDir, "screenshot", "index_screenshot.txt"))
	}

	// TODO .........
}

// Close close the httpx scan instance
func (r *Runner) Close() {
	// nolint:errcheck
	r.hm.Close()
	r.hp.Dialer.Close()
	r.ratelimiter.Stop()

	if r.options.HostMaxErrors >= 0 {
		r.HostErrorsCache.Purge()
	}
	if r.options.Screenshot {
		r.browser.Close()
	}
	if r.options.ShowStatistics {
		_ = r.stats.Stop()
	}
	//if r.options.HttpApiEndpoint != "" {
	//	_ = r.httpApiEndpoint.Stop()
	//}
	if r.options.OnClose != nil {
		r.options.OnClose()
	}

}
