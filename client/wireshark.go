package main

import (
	"github.com/SPROgster/libpcap_remote/v3/pb"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"os/exec"
	"time"
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

	log.WithField("wireshark_addr", listener.Addr().String()).Debug("starting wireshark")
	wiresharkApp := exec.Command("wireshark", "-k", "-i", "TCP@"+listener.Addr().String())
	err = wiresharkApp.Start()
	if err != nil {
		return nil, err
	}

	// Watch wireshark app
	go func() {
		_ = wiresharkApp.Wait()
		close(appChan)
		log.WithField("wireshark_addr", listener.Addr().String()).Debug("wireshark closed")
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
				log.WithField("wireshark_addr", listener.Addr().String()).Error(err)
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
	for {
		// Check if wiresharkApp wiresharkApp closed
		select {
		case <-appChan:
			log.Debug("Wireshark closed")
			close(w.DoCapture)
			return io.EOF

		case <-w.writer.connectionClosed:
			log.Debug("Wireshark stopped dump")
			return nil

		case packet, ok := <-w.PacketChannel:
			if !ok {
				return io.EOF
			}
			if err := w.pcapFormat.WritePacket(packet); err != nil {
				log.Error(err)
				return nil
			}

		default:
			timeout := time.Now().Add(10 * time.Millisecond)

			// Check for socket closure
			one := make([]byte, 256)
			if err := w.conn.SetReadDeadline(timeout); err == io.EOF {
				log.Debug("%s detected closed wireshark connection", w.conn.LocalAddr().String())
				return nil
			}
			if _, err := w.conn.Read(one); err == io.EOF {
				log.Debug("%s detected closed wireshark connection", w.conn.LocalAddr().String())
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
