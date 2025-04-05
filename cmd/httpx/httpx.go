package main

import (
	"github.com/Rain1er/httpx_go/runner"
	"github.com/projectdiscovery/gologger"
	"os"
	"os/signal"
)

func main() {
	options := runner.ParseOptions()

	httpxRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msg("detect CTRL+C：Stopping\n")
			httpxRunner.Close()
			if options.ShouldSaveResume() {
				gologger.Info().Msgf("make resume file: %s\n", runner.DefaultResumeFile)
				err := httpxRunner.SaveResumeConfig()
				if err != nil {
					gologger.Error().Msgf("could not save resume file: %s\n", err)
				}
			}
			os.Exit(1)
		}
	}() // 不仅定义了这个匿名函数，还让它立即运行
}
