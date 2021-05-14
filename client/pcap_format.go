package main

import (
	"github.com/SPROgster/libpcap_remote/v3/pb"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"io"
	"sync"
	"time"
)

type PcapFormat struct {
	writer        *pcapgo.Writer
	lock          sync.Locker
	lt			  layers.LinkType
	headerWritten bool
	snapLen       uint32
}

func NewPcapFormat(writer io.Writer, snapLen uint32) *PcapFormat {
	return &PcapFormat{
		writer:        pcapgo.NewWriter(writer),
		headerWritten: false,
		lock:          &sync.Mutex{},
		snapLen:       snapLen,
	}
}

func (p *PcapFormat) writeHeader(lt layers.LinkType) error {
	if !p.headerWritten {
		err := p.writer.WriteFileHeader(p.snapLen, lt)
		if err != nil {
			return err
		}
		p.headerWritten = true
	}
	return nil
}

func (p *PcapFormat) WritePacket(packet *pb.Packet) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.writeHeader(layers.LinkType(packet.LinkType)); err != nil {
		return err
	}

	ci := gopacket.CaptureInfo{
		Timestamp:      time.Unix(packet.Ts/time.Second.Nanoseconds(), packet.Ts%time.Second.Nanoseconds()),
		CaptureLength:  int(packet.CaptureLength),
		Length:         int(packet.Length),
		InterfaceIndex: int(packet.InterfaceIndex),
		AncillaryData:  nil,
	}

	err := p.writer.WritePacket(ci, packet.Payload)
	if err != nil {
		return err
	}

	return nil
}
