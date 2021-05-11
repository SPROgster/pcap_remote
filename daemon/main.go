package main

import (
	"context"
	"github.com/gobuffalo/envy"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"

	"github.com/SPROgster/libpcap_remote/v3/pb"
	"github.com/google/gopacket/pcap"
)

var (
	port = envy.Get("PORT", "56528")
)

type daemon struct {
	pb.UnimplementedPcapRemoteServiceServer
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
		log.Println("\nName: ", device.Name)
		log.Println("Description: ", device.Description)
		log.Println("Devices addresses: ", device.Description)
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
			Name:                 device.Name,
			Description:          device.Description,
		}
	}

	return &pb.ListInterfacesReply{
		InterfaceList:        list,
	}, nil
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
