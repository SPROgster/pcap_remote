package main

import (
	"context"
	"fmt"
	"github.com/AlexsJones/cli/cli"
	"github.com/AlexsJones/cli/command"
	"github.com/SPROgster/libpcap_remote/v3/pb"
	"github.com/gobuffalo/envy"
	uuid "github.com/nu7hatch/gouuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	port = envy.Get("PCAP_REMOTE_PORT", "56528")
)

type client struct {
	DeviceDescription
	finish  chan bool
	conn    *grpc.ClientConn
	service pb.PcapRemoteServiceClient
}

type captureWorkEntry struct {
	c      *client
	finish chan bool
}

type captureWork struct {
	uuid    *uuid.UUID
	clients []*captureWorkEntry
	stream  chan *pb.Packet
	w       *Wireshark
}

var (
	clientList = map[string]client{}
	iface      = "any"
	pcapfilter = ""
	promisc    = false
	snaplen    = uint32(9000)
	count      = uint64(0)
)

func (c *client) startDump(cw *captureWork) {
	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second*1500)
	defer cancel2()

	receiver, err := c.service.StartCapture(ctx2, &pb.StartCaptureRequest{
		Uuid:        cw.uuid.String(),
		Device:      iface,
		SnapshotLen: snaplen,
		Promiscuous: promisc,
		PcapFilter:  pcapfilter,
	})
	if err != nil {
		log.WithField("addr", c.Address).Error(err)
		return
	}

	go func() {
		packet, err := receiver.Recv()
		if err != nil {
			log.WithField("error", err).Fatal("Error occurred")
		}
		cw.stream <- packet
	}()

	select {
	case <-c.finish:
		_, err := c.service.StopCapture(ctx, &pb.StopCaptureRequest{Uuid: cw.uuid.String()})
		if err != nil {
			log.WithField("command", "stop capture").WithField("client", c.Address).Error(err)
			return
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
			clients: make([]*captureWorkEntry, 0, len(clientList)),
			w:       wireshark,
			uuid:    u,
			stream:  stream,
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
			cwe := &captureWorkEntry{
				c:      &c,
				finish: make(chan bool),
			}
			cw.clients = append(cw.clients, cwe)
			go c.startDump(&cw)
		}

		select {
		case <-signalChan:
			for _, c := range clientList {
				close(c.finish)
				close(stream)
				return
			}
		case capture, ok := <-wireshark.DoCapture:
			if ok && capture {
				continue
			}
			for _, c := range clientList {
				close(c.finish)
			}
			if !ok {
				return
			}
			close(stream)
		}
	}
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

	log.SetLevel(log.DebugLevel)

	c := cli.NewCli()

	// start
	c.AddCommand(command.Command{
		Name: "start",
		Help: "start packet capture",
		Func: func(args []string) {
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

	// Count
	c.AddCommand(command.Command{
		Name: "count",
		Help: "show or set packet capture count",
		Func: func(args []string) {
			switch len(args) {
			case 0:
				fmt.Printf("Current packets count is: %d\n", count)
			case 1:
				c, err := strconv.ParseUint(args[0], 10, 16)
				if err != nil {
					fmt.Println(err)
					return
				}
				count = c
			default:
				fmt.Println("Invalid arg count")
			}
		},
	})

	c.AddCommand(command.Command{
		Name:        "promisc",
		Help:        "",
		Func:        nil,
		SubCommands: []command.Command{
			{
				Name:        "true",
				Help:        "",
				Func: func(args []string) {
					promisc = true
				},
				SubCommands: nil,
			},
			{
				Name:        "false",
				Help:        "",
				Func: func(args []string) {
					promisc = false
				},
				SubCommands: nil,
			},
		},
	})

	// Config
	c.AddCommand(command.Command{
		Name: "config",
		Help: "",
		Func: nil,
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
				SubCommands: nil,
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
