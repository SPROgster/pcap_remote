package main

import (
	"fmt"
	"github.com/SPROgster/libpcap_remote/v3/pb"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"os/exec"
)

type Wireshark struct {
	PacketChannel <- chan *pb.Packet
	pcapFormat    *PcapFormat
	writer        wiresharkWriter
	DoCapture     chan bool
	conn          net.Conn
}

type wiresharkWriter struct {
	wireshark        *Wireshark
	connectionClosed chan bool
}

func WiresharkWriter(snapLen uint32) (*Wireshark, error) {
	w := &Wireshark{
		DoCapture:     make(chan bool),
		PacketChannel: make(chan *pb.Packet, 256),
		conn:          nil,
	}

	w.writer = wiresharkWriter{
		wireshark:        w,
		connectionClosed: make(chan bool),
	}

	appChan := make(chan bool)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	wiresharkAddr := log.Fields{"addr": listener.Addr().String()}

	log.WithFields(wiresharkAddr).Debug("Listen wireshark connection")
	wiresharkApp := exec.Command("wireshark", "-k", "-i", "TCP@"+listener.Addr().String())
	err = wiresharkApp.Start()
	if err != nil {
		return nil, err
	}
	log.WithFields(wiresharkAddr).Debug("Wireshark app started")

	// Watch wireshark app
	go func() {
		_ = wiresharkApp.Wait()
		close(appChan)
		log.WithFields(wiresharkAddr).Debug("wireshark closed")
	}()

	// Process connections
	go func() {
		defer func() {
			err := listener.Close()
			if err != nil {
				log.Error(err)
			}
		}()
		for {
			var err error
			w.conn, err = listener.Accept()
			if err != nil {
				log.WithFields(wiresharkAddr).Error(err)
				return
			}

			w.DoCapture <- true

			w.pcapFormat = NewPcapFormat(&w.writer, snapLen)

			if err := w.processConnection(appChan); err != nil {
				w.CloseConnection()
				return
			}
			w.DoCapture <- false
			w.CloseConnection()
		}
	}()

	return w, nil
}

func (w *Wireshark) processConnection(appChan chan bool) error {
	wiresharkAddr := log.Fields{"addr": w.conn.LocalAddr().String(), "remote": w.conn.RemoteAddr().String()}

	fmt.Println("Starting wireshark dump")

	for {
		// Check if wiresharkApp wiresharkApp closed
		select {
		case <-appChan:
			log.WithFields(wiresharkAddr).Debug("Wireshark closed")
			fmt.Println("Stopped dump from wireshark")
			close(w.DoCapture)
			return io.EOF

		case <-w.writer.connectionClosed:
			log.WithFields(wiresharkAddr).Debug("Wireshark stopped dump")
			fmt.Println("Stopped dump from wireshark")
			close(w.DoCapture)
			return nil

		case packet, ok := <-w.PacketChannel:
			if !ok {
				return io.EOF
			}
			if err := w.pcapFormat.WritePacket(packet); err == io.EOF {
				fmt.Println("Stopped dump from wireshark")
				//w.DoCapture <- false
				close(w.DoCapture)
				return io.EOF
			} else if err != nil {
				log.WithFields(wiresharkAddr).Error(err)
				return nil
			}
		}
	}
}

func (w *wiresharkWriter) Write(p []byte) (n int, err error) {
	if w.wireshark.conn == nil {
		return 0, io.EOF
	}

	n, err = w.wireshark.conn.Write(p)
	if err != nil {
		close(w.connectionClosed)
		return n, io.EOF
	}
	return n, nil
}

func (w *Wireshark) CloseConnection() {
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
}
