package main

import (
	"github.com/SPROgster/libpcap_remote/pb"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
	"io"
	"sync"
	"time"
)

type PcapFormat struct {
	writer        *pcapgo.Writer
	lock          sync.Locker
	lt            layers.LinkType
	headerWritten bool
	snapLen       uint32
}

var (
	f = log.Fields{"module": "PcapFormat"}
)

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
		if err == io.EOF || (err != nil && err.Error() == "EOF") {
			log.Debug("Underlying writer closed")
			return io.EOF
		}
		if err != nil {
			log.Debug(err)
			return err
		}
		p.headerWritten = true
	}
	return nil
}

func (p *PcapFormat) WritePacket(packet *pb.Packet) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.writeHeader(layers.LinkType(packet.LinkType)); err == io.EOF {
		return io.EOF
	} else if err != nil {
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
	if err == io.EOF || (err != nil && err.Error() == "EOF") {
		log.Debug("Underlying writer closed")
		return io.EOF
	}
	if err != nil {
		log.Debug(err)
		return err
	}

	return nil
}
