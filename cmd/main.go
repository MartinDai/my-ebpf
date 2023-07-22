package main

import (
	"flag"
	"fmt"
	"github.com/MartinDai/my-ebpf/pkg"
	"github.com/MartinDai/my-ebpf/pkg/model"
	"github.com/MartinDai/my-ebpf/pkg/util"
	"log"
	"os"
	"os/signal"
)

func main() {
	log.Println("[INFO] Start module")
	var configFile string
	flag.StringVar(&configFile, "config", "", "配置文件")
	flag.Parse()

	var err error
	var config *model.Config
	if config, err = util.GetConfig(configFile); err != nil {
		log.Fatal(fmt.Errorf("[ERROR] Process config error\nCause: %w", err))
	}

	module := pkg.NewModule(config.Pid)
	if err = module.Start(); err != nil {
		log.Fatalf("[INFO] Start module error, Cause:%v", err)
	}

	log.Println("[INFO] Start module successful")

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	module.Stop()

	log.Println("[INFO] Stop module successful")
}
