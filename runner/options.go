package runner

import (
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"os"
	"os/signal"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	options *Options
}

type Options struct {
	InputFile       string
	InputTargetHost goflags.StringSlice
}

func ParseOptions() *Options {
	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`httpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&options.InputFile, "list", "l", "", "input file containing list of hosts to process"),
		flagSet.StringSliceVarP(&options.InputTargetHost, "target", "u", nil, "input target host(s) to probe", goflags.CommaSeparatedStringSliceOptions),
	)

	_ = flagSet.Parse()
	return options
}

func New(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	return runner, nil
}

func ListenEnd(httpxRunner *Runner) {
	c := make(chan os.Signal, 1)   // 创建一个信号通道，用于接收操作系统发送的信号，缓冲区大小为1。
	signal.Notify(c, os.Interrupt) // 注册信号通知，将中断信号（如CTRL+C）传递到信号通道c中。

	// 启动一个goroutine，用于监听并处理接收到的中断信号。
	go func() {
		// 使用for循环持续监听信号通道c中的信号。
		// 对于通道来说，for range 会持续从通道中接收值，直到通道被关闭。实现了类似while的效果
		for range c {
			// 当接收到中断信号时，记录日志信息，提示用户程序正在退出。
			gologger.Info().Msgf("检测到 CTRL+C 按下: 正在退出\n")
			httpxRunner.Close()
			os.Exit(1)
		}
	}()
}
