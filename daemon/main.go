package main

import (
	"context"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"

	"github.com/SPROgster/libpcap_remote/v3/pb"
	"github.com/google/gopacket/pcap"
)

const (
	port = ":56528"
)

type daemon struct {
	pb.UnimplementedPcapRemoteServiceServer
}

func (d *daemon) ListInterfaces(context.Context, *pb.ListInterfacesRequest) (*pb.ListInterfacesReply, error) {
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
