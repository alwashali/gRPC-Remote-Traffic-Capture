# gRPC - Remote Traffic Caputre
Remote trafffic caputre using gRPC and golang

**Server Side**

```
$ go run server.go 
```

----

**Client Side**


```
$ client.exe 

usage of client.exe

-bytes int
    	Only grab this number bytes, then exit
  -count int
    	Only grab this number packets, then exit
  -dumppkt
    	Dump packet
  -filter string
    	Capture filter
  -interface int
    	try -listNIC before
  -listNIC
    	list network cards
  -promisc
    	Set promiscuous mode
  -remote string
    	Remote Packet Collector IP (default "127.0.0.1")
  -resolve
    	Resolve whitelisted domains
  -seconds int
    	Exit after specified seconds
  -snaplen int
    	Max bytes to capture
  -stats int
    	Output statistics every N packets (default 1000)
  -verbose
    	Verbose output
  -whitelist
    	Use whitelists, default: IP Address only, use resolve for domains
```

List Network Cards 

```
$ client.exe -listNIC true

(1)- WAN Miniport (Network Monitor):\Device\NPF_{97B0DD37-56B0-4878-920B-C8D98C796CF3}
(2)- WAN Miniport (IPv6):\Device\NPF_{394AB733-4FB7-4B71-B477-5B9206465ACD}
(3)- WAN Miniport (IP):\Device\NPF_{E951B99D-07D9-418F-BF4F-37BA38FAF993}
(4)- Bluetooth Device (Personal Area Network):\Device\NPF_{47603D45-1A17-4016-9B54-0BC8877D2B0B}
(5)- Killer(R) Wireless-AC 1550 Wireless Network Adapter (9260NGW):\Device\NPF_{D53EEBEC-8609-4FAA-A0A7-970D0FA3EEE8}
(6)- Microsoft Wi-Fi Direct Virtual Adapter #2:\Device\NPF_{8B0A359E-F590-471E-B720-744E82B11C2B}
(7)- Microsoft Wi-Fi Direct Virtual Adapter:\Device\NPF_{CC588AF9-DF42-499B-AF40-3676E10BBB78}
(8)- VirtualBox Host-Only Ethernet Adapter:\Device\NPF_{EE00E599-ACFE-43A4-8146-E483E81ED815}
(9)- Adapter for loopback traffic capture:\Device\NPF_Loopback
(10)- TAP-Windows Adapter V9:\Device\NPF_{4E71E5BE-10D5-46EA-BDBD-0D3B620DEA9A}
(11)- Killer E2500 Gigabit Ethernet Controller:\Device\NPF_{C10E7556-0272-413F-9119-3E11C764DE7A}

```


```
$ client.exe -interface 6 -r 192.168.0.8 
```
