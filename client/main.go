package main

import (
	"context"
	"github.com/gobuffalo/envy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"google.golang.org/grpc"
	"io"
	"os/exec"
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

	receiver, err := c.StartCapture(ctx2, &pb.StartCaptureRequest{
		Uuid:                 uuid.String(),
		Device:               "any",
		SnapshotLen:          9000,
		Promiscuous:          false,
		PcapFilter:           "tcp port 443",
	})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	wireshark := exec.Command("wireshark", "-k", "-i", "-")

	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	wireshark.Stdin = r
	wireshark.Start()

	writer := pcapgo.NewWriter(w)

	linkType := false

	for {
		packet, err := receiver.Recv()
		if err != nil {
			log.WithField("error", err).Fatal("Error occurred")
		}
		if linkType == false {
			if err = writer.WriteFileHeader(9000, layers.LinkType(packet.LinkType)); err != nil {
				log.Fatal(err)
			}
			linkType = true
		}

		ci := gopacket.CaptureInfo{
			Timestamp:      time.Unix(packet.Ts, 0),
			CaptureLength:  int(packet.CaptureLength),
			Length:         int(packet.Length),
			InterfaceIndex: int(packet.InterfaceIndex),
			AncillaryData:  nil,
		}

		//log.WithField("packet", *packet).Println("Packet")
		err = writer.WritePacket(ci, packet.Payload)
		if err != nil {
			log.Error(err)
			break
		}
	}

	c.StopCapture(ctx, &pb.StopCaptureRequest{Uuid: uuid.String()})
}
