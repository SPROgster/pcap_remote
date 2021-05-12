package main

import (
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"os/exec"
	"time"
)

type Wireshark struct {
	Writer     net.Conn
	FinishChan chan bool
}

func WiresharkWriter() (*Wireshark, error) {
	res := &Wireshark{
		Writer:     nil,
		FinishChan: make(chan bool),
	}

	connectionChan := make(chan bool)
	appChan := make(chan bool)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	go func() {
		log.WithField("wireshark_addr", listener.Addr().String()).Debug("starting wireshark")
		wireshark := exec.Command("wireshark", "-k", "-i", "TCP@"+listener.Addr().String())
		wireshark.Start()
		wireshark.Wait()
		close(appChan)
		log.WithField("wireshark_addr", listener.Addr().String()).Debug("wireshark closed")
	}()

	wiresharkSocket, err := listener.Accept()
	if err != nil {
		return nil, err
	}
	res.Writer = wiresharkSocket

	go func() {
		for {
			one := make([]byte, 1)
			wiresharkSocket.SetReadDeadline(time.Now())
			if _, err := wiresharkSocket.Read(one); err == io.EOF {
				log.Debug("%s detected closed wireshark connection", wiresharkSocket.LocalAddr().String())
				wiresharkSocket.Close()
				wiresharkSocket = nil
				close(connectionChan)
			} else {
				wiresharkSocket.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			}
		}
	}()

	go func() {
		select {
		case <-appChan:
			log.Debug("Wireshark closed")
			close(res.FinishChan)
		case <-connectionChan:
			log.Debug("Connection closed")
			close(res.FinishChan)
		}
	}()

	return res, nil
}
