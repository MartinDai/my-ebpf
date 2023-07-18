package pkg

import (
	_ "embed"
	"fmt"
	"github.com/MartinDai/my-ebpf/pkg/model"
	bpf "github.com/aquasecurity/libbpfgo"
)

func LoadUnlinkatModule() (*model.BpfModule, error) {
	args := bpf.NewModuleArgs{BPFObjBuff: unlinkatBpf, BPFObjName: "unlinkat"}
	module, err := bpf.NewModuleFromBufferArgs(args)

	if err != nil {
		return nil, err
	}

	if err = resizeMap(module, "events", 8192); err != nil {
		return nil, err
	}

	if err := module.BPFLoadObject(); err != nil {
		return nil, err
	}
	prog, err := module.GetProgram("kprobe__do_unlinkat")
	if err != nil {
		return nil, err
	}
	if _, err := prog.AttachKprobe("do_unlinkat"); err != nil {
		return nil, err
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := module.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		return nil, err
	}

	return &model.BpfModule{
		Module:        module,
		Prog:          prog,
		Pb:            pb,
		EventsChannel: eventsChannel,
		LostChannel:   lostChannel,
	}, nil
}

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
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

//go:embed bpf/unlinkat.bpf.o
var unlinkatBpf []byte
