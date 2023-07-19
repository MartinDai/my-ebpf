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
	log.Println("[INFO] Start unlinkat module")
	var configFile string
	flag.StringVar(&configFile, "config", "", "配置文件")
	flag.Parse()

	var err error
	var config *model.Config
	if config, err = util.GetConfig(configFile); err != nil {
		log.Fatal(fmt.Errorf("[ERROR] Process config error\nCause: %w", err))
	}

	unlinkatModule := pkg.NewUnlinkatModule(config.Pid)
	if err = unlinkatModule.Start(); err != nil {
		log.Fatalf("[INFO] Start unlinkat module error, Cause:%v", err)
	}

	log.Println("[INFO] Start unlinkat module successful")

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	unlinkatModule.Stop()

	log.Println("[INFO] Stop unlinkat module successful")
}
