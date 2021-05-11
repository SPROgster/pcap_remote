package main

import (
	"context"
	"github.com/gobuffalo/envy"
	"google.golang.org/grpc"
	"time"

	"github.com/SPROgster/libpcap_remote/v3/pb"
	"github.com/nu7hatch/gouuid"
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
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second* 1500)
	defer cancel2()

	uuid, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("Unable to generate UUID")
	}

	r, err := c.StartCapture(ctx2, &pb.StartCaptureRequest{
		Uuid:                 uuid.String(),
		Device:               "any",
		SnapshotLen:          0,
		Promiscuous:          false,
		PcapFilter:           "tcp port 443",
	})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	packet, err := r.Recv()
	if err != nil {
		log.WithField("error", err).Fatal("Error occurred")
	}
	log.WithField("packet", *packet).Println("Packet")

	c.StopCapture(ctx, &pb.StopCaptureRequest{Uuid: uuid.String()})
}
