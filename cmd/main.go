package main

import (
	"bytes"
	"encoding/binary"
	"github.com/MartinDai/my-ebpf/pkg"
	"log"
)

func main() {
	bpfModule, err := pkg.LoadUnlinkatModule()
	if err != nil {
		panic(err)
	}
	defer bpfModule.Module.Close()

	bpfModule.Pb.Start()
	defer func() {
		bpfModule.Pb.Stop()
		bpfModule.Pb.Close()
	}()

	for {
		select {
		case e := <-bpfModule.EventsChannel:
			pid := binary.LittleEndian.Uint32(e[0:4])
			fileName := string(bytes.TrimRight(e[4:], "\x00"))
			log.Printf("pid %d unlinkat %q", pid, fileName)
		case e := <-bpfModule.LostChannel:
			log.Printf("lost %d events", e)
		}
	}
}
