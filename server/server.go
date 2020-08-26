package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"remotecaputre/service"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"google.golang.org/grpc"
)

type Server struct{}

var (
	snapshotLen uint32 = 1024
	err         error
	timeout     time.Duration = -1 * time.Second
	handle      *pcap.Handle
	packetCount int = 0
)

func (s *Server) Capture(srv service.RemoteCaputre_CaptureServer) error {

	log.Println("start new server")

	file, err := os.OpenFile(
		"test.pcap",
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0666,
	)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	w := pcapgo.NewWriter(file)
	w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)

	for {

		// receive data from stream
		pkt, err := srv.Recv()
		if err != nil {
			panic(err)
		}

		// empty CaptureInfo struct
		metadata := gopacket.PacketMetadata{}
		err = json.Unmarshal(pkt.Seralizedcapturreinfo, &metadata)
		if err != nil {
			fmt.Println(err)
		}

		err = w.WritePacket(metadata.CaptureInfo, pkt.Data)
		if err != nil {
			fmt.Println(err)
		}
		packetCount++
		fmt.Printf("Received...\nPacketCount: %d ", packetCount)

	}

}

func main() {
	lis, err := net.Listen("tcp", "0.0.0.0:9000")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcserver := grpc.NewServer()
	service.RegisterRemoteCaputreServer(grpcserver, &Server{})

	fmt.Println("Server started. ")
	if err := grpcserver.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)

	}

}
