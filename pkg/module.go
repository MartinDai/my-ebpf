package pkg

import "C"
import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"github.com/MartinDai/my-ebpf/pkg/util"
	bpf "github.com/aquasecurity/libbpfgo"
	"log"
	"unsafe"
)

//#cgo CFLAGS: -I./bpf/
//#include <linux/types.h>
//#include "my.bpf.h"
import "C"

type Event struct {
	Pid      uint32
	Filename [256]byte
}

type Module struct {
	pid           int
	module        *bpf.Module
	prog          *bpf.BPFProg
	mapArgs       *bpf.BPFMap
	eventPb       *bpf.PerfBuffer
	eventsChannel chan []byte
	lostChannel   chan uint64
	stopCh        chan struct{}
}

func NewModule(pid int) *Module {
	return &Module{
		pid:           pid,
		eventsChannel: make(chan []byte),
		lostChannel:   make(chan uint64),
		stopCh:        make(chan struct{}),
	}
}

func (um *Module) Start() error {
	var err error

	bpfObjPath := ".bpf/my.bpf.o"
	if err = util.SaveFile(bpfObjPath, myBpf); err != nil {
		return err
	}

	if um.module, err = bpf.NewModuleFromFile(bpfObjPath); err != nil {
		return err
	}

	if err = um.resizeMap("events", 8192); err != nil {
		return err
	}

	if err := um.module.BPFLoadObject(); err != nil {
		return err
	}
	if um.prog, err = um.module.GetProgram("kprobe__do_unlinkat"); err != nil {
		return err
	}

	if err = um.findMaps(); err != nil {
		return err
	}

	if err = um.initArgs(); err != nil {
		return err
	}

	if _, err := um.prog.AttachKprobe("do_unlinkat"); err != nil {
		return err
	}

	um.eventPb.Start()

	go um.processEvents()

	return nil
}

func (um *Module) findMaps() error {
	var err error
	if um.mapArgs, err = um.module.GetMap("args"); err != nil {
		return err
	}
	if um.eventPb, err = um.module.InitPerfBuf("events", um.eventsChannel, um.lostChannel, 1); err != nil {
		return err
	}
	return nil
}

func (um *Module) initArgs() error {
	var zero uint32
	var err error
	var tgidFilter uint32
	if um.pid <= 0 {
		tgidFilter = 0
	} else {
		tgidFilter = uint32(um.pid)
	}
	args := C.struct_my_args{
		tgid_filter: C.uint(tgidFilter),
	}
	if err = um.mapArgs.UpdateValueFlags(unsafe.Pointer(&zero), unsafe.Pointer(&args), 0); err != nil {
		return err
	}
	return nil
}

func (um *Module) processEvents() {
	for {
		select {
		case data := <-um.eventsChannel:
			var e Event
			dataBuffer := bytes.NewBuffer(data)
			if err := binary.Read(dataBuffer, binary.LittleEndian, &e); err != nil {
				log.Printf("process event error, Cause%v\n", err)
				continue
			}
			log.Printf("pid:%d filename:%v", e.Pid, e.filename())
		case e := <-um.lostChannel:
			log.Printf("lost %d events", e)
		case <-um.stopCh:
			um.module.Close()
			return
		}
	}
}

func (um *Module) Stop() {
	if um.module == nil {
		return
	}
	close(um.stopCh)
}

func (um *Module) resizeMap(name string, size uint32) error {
	var m *bpf.BPFMap
	var err error
	if m, err = um.module.GetMap(name); err != nil {
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

func (ue Event) filename() string {
	return string(bytes.TrimRight(ue.Filename[:], "\x00"))
}

//go:embed bpf/my.bpf.o
var myBpf []byte