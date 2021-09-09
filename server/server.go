package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alwashali/gRPC-Remote-Traffic-Capture/service"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

type Server struct {
	service.UnimplementedRemoteCaputreServer
}

var (
	snapshotLen uint32 = 1024
	err         error
	timeout     time.Duration = -1 * time.Second
	handle      *pcap.Handle
)

type endpoint struct {
	Hostname      string
	IPAddress     string
	Interface     string
	TraceFileName string
	Packetcount   int
	StreamingNow  bool
}

var endpoints []endpoint

func (s *Server) GetReady(ctx context.Context, info *service.EndpointInfo) (*service.Empty, error) {
	fmt.Printf("%s is connecting ... \n", info.IPaddress)
	_, Found := s.GetEndpointInfo(info.IPaddress)
	if !Found {
		e := endpoint{
			Hostname:  info.Hostname,
			IPAddress: info.IPaddress,
			TraceFileName: info.Hostname +
				"-" +
				"(" + info.IPaddress + ") ",
			Packetcount: 0,
		}
		//Append new endpoint connection to endpoints slice
		endpoints = append(endpoints, e)
		fmt.Printf("%s added\n", info.Hostname)

	}
	return &service.Empty{}, nil
}

func (s *Server) GetEndpointInfo(addr string) (int, bool) {

	for i, e := range endpoints {
		if e.IPAddress == addr {
			return i, true
		}

	}
	return 0, false
}

func (s *Server) Capture(srv service.RemoteCaputre_CaptureServer) error {
	ctx := srv.Context()
	p, _ := peer.FromContext(ctx)
	ipaddress := strings.Split(p.Addr.String(), ":")[0]
	fmt.Println("capture started ", ipaddress)
	endpoint, Found := s.GetEndpointInfo(ipaddress)
	if !Found {
		log.Panic()
		//handle properly
	}
	file, err := os.OpenFile(
		endpoints[endpoint].TraceFileName+time.Now().Format(time.RFC850)+".pcap",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644,
	)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	//go packet writer
	w := pcapgo.NewWriter(file)
	w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)

	StreamEnd := make(chan bool)
	endpoints[endpoint].StreamingNow = true
	go func() {
		for {

			// receive data from stream
			pkt, err := srv.Recv()

			if err != nil {
				//log.Fatalf("Failed to receive the packet : %v", err)
				StreamEnd <- true
				break
			}

			// empty CaptureInfo struct
			metadata := gopacket.PacketMetadata{}
			err = json.Unmarshal(pkt.Seralizedcapturreinfo, &metadata)
			if err != nil {
				fmt.Printf("Error unmarshal the packet %s \n", err)
				continue
			}

			err = w.WritePacket(metadata.CaptureInfo, pkt.Data)

			if err != nil {
				fmt.Println(err)
			}

			endpoints[endpoint].Packetcount++

			fmt.Printf("Received...\nPacketCount: %d ", endpoints[endpoint].Packetcount)

		}

	}()

	<-StreamEnd
	log.Printf("stream ended from %s \n", endpoints[endpoint].IPAddress)
	endpoints[endpoint].StreamingNow = false
	return nil

}

func main() {
	lis, err := net.Listen("tcp", "0.0.0.0:9000")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Serve the exception list over http
	go func() {

		fs := http.FileServer(http.Dir("./public"))
		http.Handle("/", fs)

		log.Println("Listening on :8080...")
		err := http.ListenAndServe(":8080", nil)
		if err != nil {
			log.Fatal(err)
		}
	}()

	grpcserver := grpc.NewServer()
	service.RegisterRemoteCaputreServer(grpcserver, &Server{})
	fmt.Println("Server started. ")
	if err := grpcserver.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)

	}

}
