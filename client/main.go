package main

import (
	"context"
	"github.com/gobuffalo/envy"
	"google.golang.org/grpc"
	"time"

	"github.com/SPROgster/libpcap_remote/v3/pb"
	log "github.com/sirupsen/logrus"
)

var (
	address     = envy.Get("ADDRESS", "localhost")
	port        = envy.Get("PORT", "56528")
	addressPort = address + ":" + port
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(addressPort, grpc.WithInsecure(), grpc.WithBlock())
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
