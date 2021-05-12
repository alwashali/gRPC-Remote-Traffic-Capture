package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/alwashali/gRPC-Remote-Traffic-Capture/service"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"google.golang.org/grpc"
)

var (
	deviceName  string = ""
	snapshotLen int32  = 65535
	promiscuous bool   = false
	err         error
	timeout     time.Duration = -1 * time.Second
	handle      *pcap.Handle
	packetchan  = make(chan gopacket.Packet, 1000)
)

// capture packets and pass through ch channel
func capture(ch chan gopacket.Packet) {
	handle, err = pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		fmt.Printf("Error opening device %s: %v", deviceName, err)
		os.Exit(1)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		ch <- packet
	}
}

func main() {

	networkCard := flag.String("i", "eth0", "-i wlo1")
	serverIP := flag.String("r", "127.0.0.1", "-r 192.168.1.20")

	flag.Parse()
	if len(os.Args) < 3 {
		fmt.Printf("\nUsage:\n-i: Network Card \n-r: Remote server IP\n")
		fmt.Printf("Example: client -i eth0 -r 192.168.100.1\n\n")
		os.Exit(0)
	}

	if *networkCard != "" {
		deviceName = *networkCard
		conn, err := grpc.Dial(*serverIP+":9000", grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			log.Fatalf("can not connect with server %v", err)
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// create gRPC client
		client := service.NewRemoteCaputreClient(conn)

		hostname, _ := os.Hostname()
		fmt.Println(hostname)
		e := service.EndpointInfo{IPAddress: "localhost", Hostname: hostname}
		_, err = client.GetReady(ctx, &e)
		if err != nil {
			fmt.Println(err)
		}

		ServerStream, err := client.Capture(context.Background())
		if err != nil {
			log.Fatalf("open stream error %v", err)
		}
		defer ServerStream.CloseSend()
		//capture and put in channel
		go capture(packetchan)
		fmt.Printf("\nSending Packets ... \n")
		for {

			select {
			case packet, ok := <-packetchan:
				if ok {
					if IGMP := packet.Layer(layers.LayerTypeIGMP); IGMP != nil {
						continue
					}

					byteArray, err := json.Marshal(packet.Metadata())
					if err != nil {
						fmt.Println(err)
					}

					pkt := service.Packet{
						Data:                  packet.Data(),
						Seralizedcapturreinfo: byteArray,
					}

					// Send to Server
					if err := ServerStream.Send(&pkt); err != nil {
						log.Fatalf("can not send %v", err)
					}

				}

			default:
			}

		}

	}

}
