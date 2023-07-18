package main

import (
	"bytes"
	"encoding/binary"
	"github.com/MartinDai/my-ebpf/pkg"
	"log"
)

type event struct {
	Pid      uint32
	Filename [256]byte
}

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
		case data := <-bpfModule.EventsChannel:
			var e event
			dataBuffer := bytes.NewBuffer(data)
			err = binary.Read(dataBuffer, binary.LittleEndian, &e)
			log.Printf("pid %d unlinkat %v", e.Pid, e.filename())
		case e := <-bpfModule.LostChannel:
			log.Printf("lost %d events", e)
		}
	}
}

func (c event) filename() string {
	return string(bytes.TrimRight(c.Filename[:], "\x00"))
}
