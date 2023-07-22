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
	eventBuffer   *bpf.RingBuffer
	eventsChannel chan []byte
	stopCh        chan struct{}
}

func NewModule(pid int) *Module {
	return &Module{
		pid:           pid,
		eventsChannel: make(chan []byte),
		stopCh:        make(chan struct{}),
	}
}

func (m *Module) Start() error {
	var err error

	bpfObjPath := ".bpf/my.bpf.o"
	if err = util.SaveFile(bpfObjPath, myBpf); err != nil {
		return err
	}

	if m.module, err = bpf.NewModuleFromFile(bpfObjPath); err != nil {
		return err
	}

	if err = m.resizeMap("events", 8192); err != nil {
		return err
	}

	if err := m.module.BPFLoadObject(); err != nil {
		return err
	}
	if m.prog, err = m.module.GetProgram("kprobe__do_sys_openat2"); err != nil {
		return err
	}

	if err = m.findMaps(); err != nil {
		return err
	}

	if err = m.initArgs(); err != nil {
		return err
	}

	if _, err := m.prog.AttachKprobe("do_sys_openat2"); err != nil {
		return err
	}

	m.eventBuffer.Start()

	go m.processEvents()

	return nil
}

func (m *Module) findMaps() error {
	var err error
	if m.mapArgs, err = m.module.GetMap("args"); err != nil {
		return err
	}
	if m.eventBuffer, err = m.module.InitRingBuf("events", m.eventsChannel); err != nil {
		return err
	}
	return nil
}

func (m *Module) initArgs() error {
	var zero uint32
	var err error
	var tgidFilter uint32
	if m.pid <= 0 {
		tgidFilter = 0
	} else {
		tgidFilter = uint32(m.pid)
	}
	args := C.struct_my_args_t{
		tgid_filter: C.uint(tgidFilter),
	}
	if err = m.mapArgs.UpdateValueFlags(unsafe.Pointer(&zero), unsafe.Pointer(&args), 0); err != nil {
		return err
	}
	return nil
}

func (m *Module) processEvents() {
	for {
		select {
		case data := <-m.eventsChannel:
			var e Event
			dataBuffer := bytes.NewBuffer(data)
			if err := binary.Read(dataBuffer, binary.LittleEndian, &e); err != nil {
				log.Printf("process event error, Cause%v\n", err)
				continue
			}
			log.Printf("pid:%d openat:%v", e.Pid, e.filename())
		case <-m.stopCh:
			m.module.Close()
			return
		}
	}
}

func (m *Module) Stop() {
	if m.module == nil {
		return
	}
	close(m.stopCh)
}

func (m *Module) resizeMap(name string, size uint32) error {
	var bm *bpf.BPFMap
	var err error
	if bm, err = m.module.GetMap(name); err != nil {
		return err
	}
	if err = bm.Resize(size); err != nil {
		return err
	}
	if actual := bm.GetMaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}
	return nil
}

func (ue Event) filename() string {
	return string(bytes.TrimRight(ue.Filename[:], "\x00"))
}

//go:embed bpf/my.bpf.o
var myBpf []byte
