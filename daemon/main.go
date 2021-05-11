package main

import (
	"context"
	"github.com/SPROgster/libpcap_remote/v3/pb"
	"github.com/gobuffalo/envy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"sync"
)

var (
	port = envy.Get("PORT", "0.0.0.0:56528")
)

type daemon struct {
	pb.UnimplementedPcapRemoteServiceServer
	subscribers sync.Map
}

type sub struct {
	stream   *pb.PcapRemoteService_StartCaptureServer
	finished chan<- bool // finished is used to signal closure of a client subscribing goroutine
}

// ListInterfaces is fast check for lib and its initialisation
func ListInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if len(devices) == 0 {
		log.Fatal("No devices for capture")
	}

	// Print device information
	log.Println("Devices found:")
	for _, device := range devices {
		log.Println("Name: ", device.Name)
		log.Println("Description: ", device.Description)
		if len(device.Addresses) > 0 {
			log.Println("Devices addresses: ", device.Description)
		}
		for _, address := range device.Addresses {
			log.Println("- IP address: ", address.IP)
			log.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

func (d *daemon) ListInterfaces(context.Context, *pb.Empty) (*pb.ListInterfacesReply, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	list := make(map[string]*pb.ListInterfacesReply_Interface)

	for _, device := range devices {
		list[device.Name] = &pb.ListInterfacesReply_Interface{
			Name:        device.Name,
			Description: device.Description,
		}
	}

	return &pb.ListInterfacesReply{
		InterfaceList: list,
	}, nil
}

func (d *daemon) StartCapture(request *pb.StartCaptureRequest, stream pb.PcapRemoteService_StartCaptureServer) error {
	if len(request.Uuid) == 0 {
		return status.Errorf(codes.InvalidArgument, "UUID not given")
	}

	if len(request.Device) == 0 {
		return status.Errorf(codes.InvalidArgument, "Device not given")
	}

	if request.SnapshotLen == 0 {
		request.SnapshotLen = 12000
	}

	// Open device
	handle, err := pcap.OpenLive(request.Device, int32(request.SnapshotLen), request.Promiscuous, pcap.BlockForever)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	defer handle.Close()

	log.WithFields(log.Fields{"device": request.Device, "pcap-filter": request.PcapFilter}).Debug("Opened live")

	// Set filter
	filter := request.PcapFilter
	if len(filter) > 0 {
		err = handle.SetBPFFilter(filter)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		log.WithFields(log.Fields{"device": request.Device, "pcap-filter": request.PcapFilter}).Debug("Applied pcap-filter")
	}

	fin := make(chan bool)
	d.subscribers.Store(request.Uuid, sub{
		stream:   &stream,
		finished: fin,
	})
	defer d.subscribers.Delete(request.Uuid)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ctx := stream.Context()
	for {
		select {
		case packet, ok := <- packets:
			if !ok {
				return status.Error(codes.Aborted, "Capture ended")
			}
			p := new(pb.Packet)
			meta := packet.Metadata()

			p.Ts = meta.Timestamp.Unix()
			p.Vlan = 0

			copy(p.Packet, packet.Data())
			err = stream.Send(p)
			if err != nil {
				return err
			}
		case <- fin:
			log.Debug("Closing stream for %s", request.Uuid)
			return nil

		case <- ctx.Done():
			log.Debug("Client ID %s has disconnected", request.Uuid)
			return nil
		}
	}
}

func (d *daemon) StopCapture(ctx context.Context, in *pb.StopCaptureRequest) (*pb.Empty, error) {
	uuid := in.Uuid

	if work, ok := d.subscribers.Load(uuid); !ok {
		return nil, status.Errorf(codes.NotFound, "Work `%s` not found", uuid)
	} else {
		s := work.(sub)
		close(s.finished)
	}

	return &pb.Empty{}, nil
}

func main() {
	ListInterfaces()

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	pb.RegisterPcapRemoteServiceServer(s, &daemon{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
