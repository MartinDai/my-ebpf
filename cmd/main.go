package main

import (
	"github.com/MartinDai/my-ebpf/pkg"
	"log"
	"os"
	"os/signal"
)

func main() {
	unlinkatModule := pkg.NewUnlinkatModule()
	err := unlinkatModule.Start()
	if err != nil {
		log.Fatalf("Start unlinkat module error, Cause:%v", err)
	}

	log.Println("Start unlinkat module successful")

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	unlinkatModule.Stop()

	log.Println("Stop unlinkat module successful")
}
