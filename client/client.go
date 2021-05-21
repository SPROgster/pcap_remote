package main

import (
	"context"
	"fmt"
	"github.com/AlexsJones/cli/cli"
	"github.com/AlexsJones/cli/command"
	"github.com/SPROgster/libpcap_remote/pb"
	"github.com/gobuffalo/envy"
	uuid "github.com/nu7hatch/gouuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	port = envy.Get("PCAP_REMOTE_PORT", "56528")
)

type client struct {
	DeviceDescription
	conn    *grpc.ClientConn
	service pb.PcapRemoteServiceClient
}

type captureWorkJob struct {
	c      *client
	finish chan bool
	cancel context.CancelFunc
}

type captureWork struct {
	uuid   *uuid.UUID
	jobs   []*captureWorkJob
	stream chan *pb.Packet
	w      *Wireshark
}

var (
	clientList = map[string]client{}
	iface      = "any"
	pcapfilter = ""
	promisc    = false
	snaplen    = uint32(9000)
	direction  = pb.Direction_INOUT
)

func (cw *captureWork) sendPacket(packet *pb.Packet) {
	// Easy way to bypass grpc.stream.Recv blocking
	defer func() {
		_ = recover()
	}()
	cw.stream <- packet
}

func (cwe *captureWorkJob) startDump(cw *captureWork) {
	// Contact the server and print out its response.
	startCtx, cancel := context.WithCancel(context.Background())
	cwe.cancel = cancel

	finish := make(chan bool)

	receiver, err := cwe.c.service.StartCapture(startCtx, &pb.StartCaptureRequest{
		Uuid:        cw.uuid.String(),
		Device:      iface,
		SnapshotLen: snaplen,
		Promiscuous: promisc,
		PcapFilter:  pcapfilter,
		Direction:   direction,
	})
	if err != nil {
		log.WithField("addr", cwe.c.Address).Error(err)
		return
	}

	go func() {
		ctx := receiver.Context()

		for {
			packet, err := receiver.Recv()
			select {
			case <-finish:
				log.WithField("client", cwe.c.Address).Debug("Finishing receiver")
				return

			case <-ctx.Done():
				log.WithField("client", cwe.c.Address).Debug("Context done")
				return

			default:
				if err != nil {
					log.WithField("error", err).Error("Error occurred")
					return
				}
				cw.sendPacket(packet)
			}
		}
	}()

	select {
	case <-cwe.finish:
		defer close(finish)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		_, err := cwe.c.service.StopCapture(ctx, &pb.StopCaptureRequest{Uuid: cw.uuid.String()})
		if err != nil {
			s, ok := status.FromError(err)
			if !ok {
				log.WithField("command", "stop capture").WithField("client", cwe.c.Address).Error(err)
				return
			}
			if s.Code() == codes.NotFound {
				log.WithField("command", "stop capture").WithField("client", cwe.c.Address).Debug("Already stopped")
				return
			}
		}
		return
	}
}

func startCapture() {
	signalChan := make(chan os.Signal)
	defer close(signalChan)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	wireshark, err := WiresharkWriter(snaplen)
	if err != nil {
		fmt.Println(err)
	}

	for {
		u, err := uuid.NewV4()
		if err != nil {
			log.Errorf("Unable to generate UUID")
			return
		}

		stream := make(chan *pb.Packet, 256)

		wireshark.PacketChannel = stream

		cw := captureWork{
			jobs:   make([]*captureWorkJob, 0, len(clientList)),
			w:      wireshark,
			uuid:   u,
			stream: stream,
		}

		// in case of multiple false after wireshark stop
		for {
			capture, ok := <-wireshark.DoCapture
			if !ok {
				return
			}
			if capture {
				break
			}
		}

		for _, c := range clientList {
			cwe := &captureWorkJob{
				c:      &c,
				finish: make(chan bool),
			}
			cw.jobs = append(cw.jobs, cwe)
			go cwe.startDump(&cw)
		}

		for {
			select {
			case <-signalChan:
				log.Debug("Receiver SIGINT")
				cw.stop()
				return
			case capture, ok := <-wireshark.DoCapture:
				if ok && capture {
					continue
				}
				log.Debug("Stopping capture from frontend")
				cw.stop()

				return
			}
		}
	}
}

func (cw *captureWork) stop() {
	for _, c := range cw.jobs {
		close(c.finish)
		c.cancel()
	}
	close(cw.stream)
}

func connect(name string, address string) {
	if !strings.Contains(address, ":") {
		address = address + ":" + port
	}

	if _, exists := clientList[name]; exists {
		fmt.Printf("`%s` already connected\n", address)
		return
	}

	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.WithField("error", err).Errorf("did not connect to %s: %v", address, err)
	}
	service := pb.NewPcapRemoteServiceClient(conn)

	clientList[name] = client{
		DeviceDescription: DeviceDescription{
			Address: address,
		},
		conn:    conn,
		service: service,
	}
}

func disconnect(name string) {
	if _, exists := clientList[name]; exists {
		fmt.Printf("address `%s` not exists\n", name)
		return
	}

	a := clientList[name]
	delete(clientList, name)

	if err := a.conn.Close(); err != nil {
		log.WithField("name", name).Error(err)
	}
}

func initConfig() {
	c := NewConfig()
	if err := c.Load(); err != nil {
		fmt.Println(err)
		return
	}

	clientList = make(map[string]client)
	for n, v := range c.Devices {
		connect(n, v.Address)
	}
}

func main() {
	initConfig()

	c := cli.NewCli()

	// start
	c.AddCommand(command.Command{
		Name: "start",
		Help: "start packet capture",
		Func: func(args []string) {
			if len(args) != 0 {
				fmt.Println("Extra arguments")
				return
			}

			startCapture()
		},
	})

	// devices
	c.AddCommand(command.Command{
		Name: "devices",
		Help: "list current devices",
		Func: func(args []string) {
			fmt.Println("Current devices:")
			for name, v := range clientList {
				fmt.Printf("		%s : %s\n", name, v.Address)
			}
			fmt.Println("")
		},
		SubCommands: []command.Command{
			{
				Name: "add",
				Help: "add <name> <address:[port]> - add device address to capture",
				Func: func(args []string) {
					if len(args)%2 != 0 {
						fmt.Println("Invalid arguments count")
					}

					name := ""
					for i, v := range args {
						if i%2 == 0 {
							name = v
						} else {
							connect(name, v)
						}
					}
				},
				SubCommands: nil,
			},
			{
				Name: "delete",
				Help: "delete device from capture list",
				Func: func(args []string) {
					if len(args) == 0 {
						fmt.Println("address needed")
						return
					}

					for _, v := range args {
						disconnect(v)
					}
				},
				SubCommands: nil,
			},
		},
	})

	// interface
	c.AddCommand(command.Command{
		Name: "interface",
		Help: "show or set capture interface",
		Func: func(args []string) {
			switch len(args) {
			case 0:
				fmt.Printf("Current interface is: %s\n", iface)
			case 1:
				iface = args[0]
			default:
				fmt.Println("Invalid arg count")
			}
		},
	})

	// pcap-filter
	c.AddCommand(command.Command{
		Name: "pcap-filter",
		Help: "show or set pcap-filter",
		Func: func(args []string) {
			switch len(args) {
			case 0:
				fmt.Printf("Current pcap-filter is: `%s`\n", pcapfilter)
			default:
				pcapfilter = strings.Join(args, " ")
			}
		},
	})

	// Promisc
	c.AddCommand(command.Command{
		Name: "promisc",
		Help: "",
		Func: func(args []string) {
			if len(args) != 0 {
				fmt.Println("Extra arguments")
			}

			fmt.Println("Promisc: ", promisc)
		},
		SubCommands: []command.Command{
			{
				Name: "true",
				Help: "",
				Func: func(args []string) {
					if len(args) != 0 {
						fmt.Println("Extra arguments")
					}

					promisc = true
				},
			},
			{
				Name: "false",
				Help: "",
				Func: func(args []string) {
					if len(args) != 0 {
						fmt.Println("Extra arguments")
					}

					promisc = false
				},
			},
		},
	})

	// Direction
	c.AddCommand(command.Command{
		Name: "direction",
		Help: "Send/receive direction direction for which packets should be captured",
		Func: func(args []string) {
			if len(args) != 0 {
				fmt.Println("Extra arguments")
			}

			direction = pb.Direction_INOUT
		},
		SubCommands: []command.Command{
			{
				Name: "inout",
				Help: "Send/receive direction direction for which packets should be captured",
				Func: func(args []string) {
					if len(args) != 0 {
						fmt.Println("Extra arguments")
					}

					direction = pb.Direction_INOUT
				},
			},
			{
				Name: "in",
				Help: "",
				Func: func(args []string) {
					if len(args) != 0 {
						fmt.Println("Extra arguments")
					}

					direction = pb.Direction_IN
				},
			},
			{
				Name: "out",
				Help: "",
				Func: func(args []string) {
					if len(args) != 0 {
						fmt.Println("Extra arguments")
					}

					direction = pb.Direction_OUT
				},
			},
		},
	})

	// Config
	c.AddCommand(command.Command{
		Name: "config",
		Help: "",
		Func: func(args []string) {
			fmt.Println("Invalid command")
		},
		SubCommands: []command.Command{
			{
				Name: "save",
				Help: "",
				Func: func(args []string) {
					if len(args) != 0 {
						fmt.Println("Extra arguments")
						return
					}

					dl := make(DeviceList, len(clientList))
					for n, v := range clientList {
						dl[n] = v.DeviceDescription
					}
					c := &Config{
						Devices: dl,
					}
					if err := c.Save(); err != nil {
						fmt.Println(err)
					}
				},
			},
			{
				Name: "load",
				Func: func(args []string) {
					if len(args) != 0 {
						fmt.Println("Extra arguments")
						return
					}

					initConfig()
				},
			},
		},
	})

	c.Run()
}
