package main

import (
	"github.com/Rain1er/httpx_go/runner"
	"github.com/projectdiscovery/gologger"
)

func main() {
	// 1. 解析输入参数
	options := runner.ParseOptions()

	//2. 创建扫描实例
	httpxRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("无法创建运行器: %s\n", err)
	}

	//3. 监听用户是否手动结束进程
	runner.ListenEnd(httpxRunner)

	httpxRunner.RunEnumeration() // 运行核心枚举逻辑
	httpxRunner.Close()          // 关闭运行器
}
