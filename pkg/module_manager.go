package pkg

import (
	_ "embed"
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
)

//go:embed bpf/unlinkat.bpf.o
var unlinkatBpf []byte

const btf = "should not be used" // canary to detect we got relocations

func LoadUnlinkatModule() (*bpf.Module, error) {
	//args := bpf.NewModuleArgs{BPFObjBuff: unlinkatBpf, BPFObjName: "unlinkat", BTFObjPath: btf}
	//bpfModule, err := bpf.NewModuleFromBufferArgs(args)

	bpfModule, err := bpf.NewModuleFromFile("unlinkat.bpf.o")

	if err != nil {
		return nil, err
	}

	return bpfModule, nil
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
