package main

import (
	"context"
	"google.golang.org/grpc"
	"time"

	"github.com/SPROgster/libpcap_remote/v3/pb"
	log "github.com/sirupsen/logrus"
)

const (
	address     = "localhost:56528"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewPcapRemoteServiceClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.ListInterfaces(ctx, &pb.ListInterfacesRequest{})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", r.GetInterfaceList())
}
