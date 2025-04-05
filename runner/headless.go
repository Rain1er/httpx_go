package runner

import (
	"github.com/go-rod/rod"
	"os"
)

type Browser struct {
	tempDir string
	engine  *rod.Browser
	// TODO: Remove the Chrome PID kill code in favor of using Leakless(true).
	// This change will be made if there are no complaints about zombie Chrome processes.
	// Reference: https://github.com/projectdiscovery/httpx/pull/1426
	// pids    map[int32]struct{}
}

func (b *Browser) Close() {
	b.engine.Close()
	os.RemoveAll(b.tempDir)
}
