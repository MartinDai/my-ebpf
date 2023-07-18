package pkg

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"log"
)

type UnlinkatEvent struct {
	Pid      uint32
	Filename [256]byte
}

type UnlinkatModule struct {
	module        *bpf.Module
	eventsChannel chan []byte
	lostChannel   chan uint64
	stopCh        chan struct{}
}

func NewUnlinkatModule() *UnlinkatModule {
	return &UnlinkatModule{
		eventsChannel: make(chan []byte),
		lostChannel:   make(chan uint64),
		stopCh:        make(chan struct{}),
	}
}

func (bm *UnlinkatModule) Start() error {
	var err error
	args := bpf.NewModuleArgs{BPFObjBuff: unlinkatBpf, BPFObjName: "unlinkat"}
	bm.module, err = bpf.NewModuleFromBufferArgs(args)

	if err != nil {
		return err
	}

	if err = bm.resizeMap("events", 8192); err != nil {
		return err
	}

	if err := bm.module.BPFLoadObject(); err != nil {
		return err
	}
	prog, err := bm.module.GetProgram("kprobe__do_unlinkat")
	if err != nil {
		return err
	}
	if _, err := prog.AttachKprobe("do_unlinkat"); err != nil {
		return err
	}

	pb, err := bm.module.InitPerfBuf("events", bm.eventsChannel, bm.lostChannel, 1)
	if err != nil {
		return err
	}

	pb.Start()

	go bm.processEvents()

	return nil
}

func (bm *UnlinkatModule) processEvents() {
	for {
		select {
		case data := <-bm.eventsChannel:
			var e UnlinkatEvent
			dataBuffer := bytes.NewBuffer(data)
			err := binary.Read(dataBuffer, binary.LittleEndian, &e)
			if err != nil {
				log.Printf("process event error, Cause%v\n", err)
				continue
			}
			log.Printf("pid %d unlinkat %v", e.Pid, e.filename())
		case e := <-bm.lostChannel:
			log.Printf("lost %d events", e)
		case <-bm.stopCh:
			bm.module.Close()
			return
		}
	}
}

func (bm *UnlinkatModule) Stop() {
	if bm.module == nil {
		return
	}
	close(bm.stopCh)
}

func (bm *UnlinkatModule) resizeMap(name string, size uint32) error {
	m, err := bm.module.GetMap(name)
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
