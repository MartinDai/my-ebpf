package pkg

import "C"
import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"log"
	"unsafe"
)

//#cgo CFLAGS: -I./bpf/
//#include <linux/types.h>
//#include "unlinkat.bpf.h"
import "C"

type UnlinkatEvent struct {
	Pid      uint32
	Filename [256]byte
}

type UnlinkatModule struct {
	pid           int
	module        *bpf.Module
	mapArgs       *bpf.BPFMap
	eventPb       *bpf.PerfBuffer
	eventsChannel chan []byte
	lostChannel   chan uint64
	stopCh        chan struct{}
}

func NewUnlinkatModule(pid int) *UnlinkatModule {
	return &UnlinkatModule{
		pid:           pid,
		eventsChannel: make(chan []byte),
		lostChannel:   make(chan uint64),
		stopCh:        make(chan struct{}),
	}
}

func (um *UnlinkatModule) Start() error {
	var err error
	args := bpf.NewModuleArgs{BPFObjBuff: unlinkatBpf, BPFObjName: "unlinkat"}
	um.module, err = bpf.NewModuleFromBufferArgs(args)

	if err != nil {
		return err
	}

	if err = um.resizeMap("events", 8192); err != nil {
		return err
	}

	if err := um.module.BPFLoadObject(); err != nil {
		return err
	}
	prog, err := um.module.GetProgram("kprobe__do_unlinkat")
	if err != nil {
		return err
	}

	if err = um.findMaps(); err != nil {
		return err
	}

	if err = um.initArgs(); err != nil {
		return err
	}

	if _, err := prog.AttachKprobe("do_unlinkat"); err != nil {
		return err
	}

	um.eventPb.Start()

	go um.processEvents()

	return nil
}

func (um *UnlinkatModule) findMaps() error {
	var err error
	if um.mapArgs, err = um.module.GetMap("args"); err != nil {
		return err
	}
	if um.eventPb, err = um.module.InitPerfBuf("events", um.eventsChannel, um.lostChannel, 1); err != nil {
		return err
	}
	return nil
}

func (um *UnlinkatModule) initArgs() error {
	var zero uint32
	var err error
	var tgidFilter uint32
	if um.pid <= 0 {
		tgidFilter = 0
	} else {
		tgidFilter = uint32(um.pid)
	}
	args := C.struct_unlinkat_args{
		tgid_filter: C.uint(tgidFilter),
	}
	err = um.mapArgs.UpdateValueFlags(unsafe.Pointer(&zero), unsafe.Pointer(&args), 0)
	if err != nil {
		return err
	}
	return nil
}

func (um *UnlinkatModule) processEvents() {
	for {
		select {
		case data := <-um.eventsChannel:
			var e UnlinkatEvent
			dataBuffer := bytes.NewBuffer(data)
			err := binary.Read(dataBuffer, binary.LittleEndian, &e)
			if err != nil {
				log.Printf("process event error, Cause%v\n", err)
				continue
			}
			log.Printf("pid %d unlinkat %v", e.Pid, e.filename())
		case e := <-um.lostChannel:
			log.Printf("lost %d events", e)
		case <-um.stopCh:
			um.module.Close()
			return
		}
	}
}

func (um *UnlinkatModule) Stop() {
	if um.module == nil {
		return
	}
	close(um.stopCh)
}

func (um *UnlinkatModule) resizeMap(name string, size uint32) error {
	m, err := um.module.GetMap(name)
	if err != nil {
		return err
	}
	if err = m.Resize(size); err != nil {
		return err
	}
	if actual := m.GetMaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}
	return nil
}

func (ue UnlinkatEvent) filename() string {
	return string(bytes.TrimRight(ue.Filename[:], "\x00"))
}

//go:embed bpf/unlinkat.bpf.o
var unlinkatBpf []byte
