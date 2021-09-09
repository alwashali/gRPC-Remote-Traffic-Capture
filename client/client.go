package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/alwashali/gRPC-Remote-Traffic-Capture/service"

	valid "github.com/asaskevich/govalidator"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"google.golang.org/grpc"
)

var (
	deviceName       string = ""
	snapshotLen      int32  = 65535
	promiscuous      bool   = false
	err              error
	timeout          = pcap.BlockForever
	handle           *pcap.Handle
	OS               string = ""
	done             bool   = false // for signaling ctrl+c
	errorsMap        map[string]uint
	errorsMapMutex   sync.Mutex
	errors           uint
	count            int = 0
	bytes            int = 0
	sendchan             = make(chan service.Packet, 500)
	whitelistedHosts []string
	whitelistFilter  string
)

//Flag options

var networkCard = flag.Int("interface", 0, "try -listNIC before")
var snaplen = flag.Int("snaplen", 0, "Max bytes to capture")
var serverIP = flag.String("remote", "127.0.0.1", "Remote Packet Collector IP")
var dumpOption = flag.Bool("dumppkt", false, "Dump packet")
var listNICsOption = flag.Bool("listNIC", false, "list network cards")
var captureFilter = flag.String("filter", "", "Capture filter")
var resolveExceptions = flag.Bool("resolve", false, "Resolve whitelisted domains")
var promisc = flag.Bool("promisc", false, "Set promiscuous mode")
var maxcount = flag.Int("count", 0, "Only grab this number packets, then exit")
var maxbytes = flag.Int("bytes", 0, "Only grab this number bytes, then exit")
var statsevery = flag.Int("stats", 1000, "Output statistics every N packets")
var verbose = flag.Bool("verbose", false, "Verbose output")
var whitelisting = flag.Bool("whitelist", false, "Use whitelists, default: IP Address only, use resolve for domains")
var timer = flag.Int("seconds", 0, "Exit after specified seconds")

// get ip address of network interface by name
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

// return card raw name by number, shown in -l option
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

func verbosePrint(msg string) {
	if *verbose {
		fmt.Println(msg)
	}
}

func buildFilter() {
	count := 0
	resp, err := http.Get(fmt.Sprintf("http://%s:8080/exceptions.list", *serverIP))
	if err != nil {
		log.Fatalln(err)
	}

	whitelistFilter = fmt.Sprintf("not host %s ", *serverIP)

	scanner := bufio.NewScanner(resp.Body)
	defer resp.Body.Close()

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	for scanner.Scan() {
		line := scanner.Text()

		if valid.IsDNSName(line) {

			if *resolveExceptions {
				ips, _ := r.LookupHost(context.Background(), line)
				for _, ip := range ips {
					whitelistFilter += fmt.Sprintf("and not host %s ", ip)

				}
				time.Sleep(50 * time.Millisecond)
				count++

			}

		} else {
			whitelistFilter += fmt.Sprintf("and not host %s ", line)
			count++
		}
	}

	whitelistFilter += *captureFilter

	verbosePrint(fmt.Sprintf("Number of hosts whitelisted: %d", count))

}

func main() {

	if runtime.GOOS == "windows" {
		OS = "Windows"
	} else {
		OS = "Linux"
	}

	flag.Parse()

	if len(os.Args) < 3 {
		flag.Usage()
		os.Exit(0)
	}

	if *listNICsOption {
		count := 0
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Devices found:")
		if OS == "Windows" {
			fmt.Println("")
			for _, device := range devices {
				count++
				fmt.Printf("(%d)- %s:%s\n", count, device.Description, device.Name)
			}
			os.Exit(0)
		} else {
			for _, device := range devices {
				count++
				fmt.Printf("(%d)- %s\n", count, device.Name)
			}
			os.Exit(0)
		}
	}

	if *networkCard > 0 {
		if *snaplen != 0 {
			snapshotLen = int32(*snaplen)
		}
		deviceName, err = NICByNumber(*networkCard)

		if *promisc {
			promiscuous = true
		}
		handle, err = pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
		if err != nil {
			fmt.Printf("Error opening device %s: %v", deviceName, err)
			os.Exit(1)
		}

		// filter unwanted traffic using whitelisting or capture filters

		if *whitelisting || *captureFilter != "" {
			buildFilter()
			verbosePrint(whitelistFilter)
			if err := handle.SetBPFFilter(whitelistFilter); err != nil {
				log.Fatal(err)
			}

		} else {
			fmt.Println(*captureFilter)
			whitelistFilter = fmt.Sprintf("not host %s", *serverIP)
			verbosePrint(whitelistFilter)
			if err := handle.SetBPFFilter(whitelistFilter); err != nil {
				log.Fatal(err)
			}

		}

		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		if err != nil {
			panic("No interface found")
		}
		conn, err := grpc.Dial(*serverIP+":9000", grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			log.Fatalf("can not connect with server %v", err)
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		// create gRPC client
		client := service.NewRemoteCaputreClient(conn)

		hostname, _ := os.Hostname()
		IP, err := GetIpByInterface(deviceName)
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

		go func() {
			for {
				select {
				case pkt := <-sendchan:
					err = ServerStream.Send(&pkt)
					if err == io.EOF {
						fmt.Printf("\nReceived EOF: %v\n", err)

					} else if err != nil {
						log.Fatalf("can not send %v", err)
					}
				}
			}
		}()

		packets := packetSource.Packets()
		fmt.Println("Streaming Packets (CTRL + C) to abort")

		// // timer
		timeMan := time.NewTimer(time.Duration(*timer) * time.Second)

		for {

			select {
			case packet := <-packets:
				if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
					//verbosePrint("Unusable packet")
					continue
				}
				count++
				data := packet.Data()
				bytes += len(data)
				if *verbose {
					if count%100 == 0 {
						fmt.Printf("sent #%d packets\n", count)
					}

				}
				if *dumpOption {
					fmt.Printf("Packet content (%d/0x%x)\n%s\n", len(data), len(data), hex.Dump(data))
				}

				byteArray, err := json.Marshal(packet.Metadata())
				if err != nil {
					fmt.Println(err)
				}
				pkt := service.Packet{
					Data:                  data,
					Seralizedcapturreinfo: byteArray,
				}

				//fmt.Println("debug ", *maxcount)
				if *maxcount != 0 && count >= *maxcount {
					fmt.Printf("\nExiting ...")
					fmt.Printf("\nCaptured %d packets \n", count)
					os.Exit(0)
				}

				if *maxbytes != 0 && bytes >= *maxbytes {
					fmt.Printf("\nExiting ...")
					fmt.Printf("\nPacket Size %d bytes \n", bytes)
					os.Exit(0)
				}
				sendchan <- pkt
			}
			if *timer != 0 {
				go func() {
					select {
					case <-timeMan.C:
						fmt.Println("Time up, exiting")
						os.Exit(0)
					}
				}()

			}
		}

	} else {
		fmt.Printf("\nInterface number not provided\n\n")
		flag.Usage()
	}
}
