package model

import bpf "github.com/aquasecurity/libbpfgo"

type BpfModule struct {
	Module        *bpf.Module
	Prog          *bpf.BPFProg
	Pb            *bpf.PerfBuffer
	EventsChannel chan []byte
	LostChannel   chan uint64
}
