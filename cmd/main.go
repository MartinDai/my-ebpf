package main

import (
	"flag"
	"fmt"
	"github.com/MartinDai/my-ebpf/pkg"
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

	config, err := util.GetConfig(configFile)
	if err != nil {
		log.Fatal(fmt.Errorf("[ERROR] Process config error\nCause: %w", err))
	}

	unlinkatModule := pkg.NewUnlinkatModule(config.Pid)
	err = unlinkatModule.Start()
	if err != nil {
		log.Fatalf("[INFO] Start unlinkat module error, Cause:%v", err)
	}

	log.Println("[INFO] Start unlinkat module successful")

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	unlinkatModule.Stop()

	log.Println("[INFO] Stop unlinkat module successful")
}
