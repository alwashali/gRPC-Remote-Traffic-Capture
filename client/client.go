package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
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
	packetchan         = make(chan gopacket.Packet, 1000)
	OS          string = ""
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

// get ip address of a specific network interface
func GetIpByInterface(NetwrokCard string) (string, error) {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		if device.Name == NetwrokCard {
			for _, i := range device.Addresses {
				ip := i.IP
				//if ip is not an IPv4 address, To4 returns nil
				err := ip.To4()
				if err != nil {
					return ip.String(), nil

				}

			}
		}

	}
	return "", nil
}

// return card raw name by number shown in -l option
func NICByNumber(opt int) (string, error) {

	count := 0
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		count++
		if count == opt {
			return device.Name, nil
		}
	}

	return "", fmt.Errorf("Interface not found")

}

func main() {
	var listNICsOption bool

	networkCard := flag.Int("i", 0, "try -l before")
	serverIP := flag.String("r", "127.0.0.1", "-r 192.168.1.20")
	flag.BoolVar(&listNICsOption, "l", false, "list network cards")
	if runtime.GOOS == "windows" {
		OS = "Windows"
	} else {
		OS = "Linux"
	}

	flag.Parse()

	if len(os.Args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("	-i: Network Card Number, see option -l")
		fmt.Println("	-r: Remote server IP")
		fmt.Println("	-l: List NIC names (Useful for Windows)")
		fmt.Printf("\nExample: client -i 2 -r 192.168.100.1\n\n")
		os.Exit(0)
	}

	if listNICsOption {
		count := 0
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Devices found:")

		if OS == "Windows" {

			for _, device := range devices {
				count++
				fmt.Printf("\n(%d)- %s:%s", count, device.Description, device.Name)
			}
		} else {
			for _, device := range devices {
				count++
				fmt.Printf("\n(%d)- %s", count, device.Name)
			}

		}

	}

	if *networkCard > 0 {
		deviceName, err = NICByNumber(*networkCard)
		if err != nil {
			panic("No interface found")
		}

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
		IP, err := GetIpByInterface(deviceName)
		fmt.Println(IP)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		e := service.EndpointInfo{IPaddress: IP, Hostname: hostname, Interface: deviceName}
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
