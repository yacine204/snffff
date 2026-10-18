package cli

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"packet_sniffer/internal"
	"sync"
	"syscall"
	"time"
)

const (
	demoETHIPv4 = 0x0800
	demoETHIPv6 = 0x86DD
	demoETHARP  = 0x0806
)

func htons(x uint16) uint16 {
	return (x >> 8) | (x << 8)
}

var PacketMutex sync.Mutex
var Notify = make(chan int, 8192)
var Packet []internal.ETH

var packetWorkerOnce sync.Once

func startPacketWorker() {
	packetWorkerOnce.Do(func() {
		go internal.PacketWorker()
	})
}

func pushPacket(eth internal.ETH) {
	PacketMutex.Lock()
	Packet = append(Packet, eth)
	idx := len(Packet) - 1
	PacketMutex.Unlock()

	select {
	case Notify <- idx:
	default:
	}
}

func putUint16(dst *[2]byte, value uint16) {
	binary.BigEndian.PutUint16(dst[:], value)
}

func putUint32(dst *[4]byte, value uint32) {
	binary.BigEndian.PutUint32(dst[:], value)
}

func randomPayload(r *rand.Rand, minSize, maxSize int) []byte {
	if maxSize < minSize {
		maxSize = minSize
	}
	size := minSize
	if maxSize > minSize {
		size += r.Intn(maxSize - minSize + 1)
	}
	letters := []byte("hi lol")
	data := make([]byte, size)
	for idx := range data {
		data[idx] = letters[r.Intn(len(letters))]
	}
	return data
}

type demoFlow struct {
	srcMAC    [6]byte
	dstMAC    [6]byte
	srcIP     []byte
	dstIP     []byte
	srcPort   uint16
	dstPort   uint16
	ipVersion internal.L3Protocols
	nextSeq   uint32
}

func newDemoTCPPacket(r *rand.Rand, flow *demoFlow) (internal.ETH, *internal.TCP) {
	data := randomPayload(r, 8, 32)
	tcp := &internal.TCP{}
	putUint16(&tcp.Source_port, flow.srcPort)
	putUint16(&tcp.Dest_port, flow.dstPort)
	putUint32(&tcp.Sequence_number, flow.nextSeq)
	flow.nextSeq += uint32(len(data))
	tcp.Data_offset = 5
	tcp.Control_flags = 0x18
	putUint16(&tcp.Window_size, 4096)
	putUint16(&tcp.Check_sum, uint16(r.Intn(0xffff)))
	putUint16(&tcp.Urgent_pointer, 0)
	tcp.Data = data
	tcp.Source_ip = append([]byte(nil), flow.srcIP...)
	tcp.Dest_ip = append([]byte(nil), flow.dstIP...)
	tcp.IpVersion = flow.ipVersion

	eth := internal.ETH{
		Header:         &internal.ETH_HEADER{},
		Trailer:        &internal.ETH_TRAILER{},
		Payload:        data,
		Inner_Protocol: flow.ipVersion,
	}
	copy(eth.Header.S_MAC[:], flow.srcMAC[:])
	copy(eth.Header.D_MAC[:], flow.dstMAC[:])
	if flow.ipVersion == internal.IPV6 {
		putUint16(&eth.Header.ETH_TYPE, demoETHIPv6)
		ip6 := &internal.IP6{Header: &internal.IPV6_H{}, Payload: data, Inner: tcp}
		ip6.Header.Version = 6
		ip6.Header.TrafficClass = uint8(r.Intn(0xff))
		ip6.Header.FlowLabel = uint32(r.Intn(0x000fffff))
		putUint16(&ip6.Header.PayloadLen, uint16(20+len(data)))
		ip6.Header.NextHeader = 6
		ip6.Header.HopLimit = 64
		copy(ip6.Header.SourceAddr[:], flow.srcIP)
		copy(ip6.Header.DestAddr[:], flow.dstIP)
		eth.Inner = ip6
		return eth, tcp
	}

	putUint16(&eth.Header.ETH_TYPE, demoETHIPv4)
	ip4 := &internal.IP4{Header: &internal.IPV4_H{}, Payload: data, Inner: tcp}
	ip4.Header.Version = 4
	ip4.Header.IHL = 5
	ip4.Header.TOS = uint8(r.Intn(0xff))
	putUint16(&ip4.Header.TotalLength, uint16(20+len(data)))
	putUint16(&ip4.Header.Indent, uint16(r.Intn(0xffff)))
	ip4.Header.Flags = 2
	ip4.Header.FragOffset = 0
	ip4.Header.TTL = 64
	ip4.Header.Protocol = 6
	putUint16(&ip4.Header.HeaderCS, uint16(r.Intn(0xffff)))
	copy(ip4.Header.SourceAddr[:], flow.srcIP)
	copy(ip4.Header.DestAddr[:], flow.dstIP)
	eth.Inner = ip4
	return eth, tcp
}

func newDemoUDPPacket(r *rand.Rand, flow *demoFlow) internal.ETH {
	data := randomPayload(r, 6, 24)
	udp := &internal.UDP{Header: &internal.UDP_H{}, Udp_data: data}
	putUint16(&udp.Header.Source_port, flow.srcPort)
	putUint16(&udp.Header.Dest_port, flow.dstPort)
	putUint16(&udp.Header.Check_sum, uint16(r.Intn(0xffff)))
	putUint16(&udp.Header.Length, uint16(8+len(data)))

	eth := internal.ETH{
		Header:         &internal.ETH_HEADER{},
		Trailer:        &internal.ETH_TRAILER{},
		Payload:        data,
		Inner_Protocol: flow.ipVersion,
	}
	copy(eth.Header.S_MAC[:], flow.srcMAC[:])
	copy(eth.Header.D_MAC[:], flow.dstMAC[:])

	if flow.ipVersion == internal.IPV6 {
		putUint16(&eth.Header.ETH_TYPE, demoETHIPv6)
		ip6 := &internal.IP6{Header: &internal.IPV6_H{}, Payload: data, Inner: udp}
		ip6.Header.Version = 6
		ip6.Header.TrafficClass = uint8(r.Intn(0xff))
		ip6.Header.FlowLabel = uint32(r.Intn(0x000fffff))
		putUint16(&ip6.Header.PayloadLen, uint16(8+len(data)))
		ip6.Header.NextHeader = 17
		ip6.Header.HopLimit = 64
		copy(ip6.Header.SourceAddr[:], flow.srcIP)
		copy(ip6.Header.DestAddr[:], flow.dstIP)
		eth.Inner = ip6
		return eth
	}

	putUint16(&eth.Header.ETH_TYPE, demoETHIPv4)
	ip4 := &internal.IP4{Header: &internal.IPV4_H{}, Payload: data, Inner: udp}
	ip4.Header.Version = 4
	ip4.Header.IHL = 5
	ip4.Header.TOS = uint8(r.Intn(0xff))
	putUint16(&ip4.Header.TotalLength, uint16(20+8+len(data)))
	putUint16(&ip4.Header.Indent, uint16(r.Intn(0xffff)))
	ip4.Header.Flags = 2
	ip4.Header.FragOffset = 0
	ip4.Header.TTL = 64
	ip4.Header.Protocol = 17
	putUint16(&ip4.Header.HeaderCS, uint16(r.Intn(0xffff)))
	copy(ip4.Header.SourceAddr[:], flow.srcIP)
	copy(ip4.Header.DestAddr[:], flow.dstIP)
	eth.Inner = ip4
	return eth
}

func newDemoARPPacket(r *rand.Rand) internal.ETH {
	arp := &internal.ARP_H{}
	putUint16(&arp.HardwareType, 1)
	putUint16(&arp.ProtocolType, demoETHIPv4)
	arp.HardwareAddrLen = 6
	arp.ProtocolAddrLen = 4
	if r.Intn(2) == 0 {
		putUint16(&arp.Operation, 1)
	} else {
		putUint16(&arp.Operation, 2)
	}
	copy(arp.SenderHardwareAddr[:], []byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
	copy(arp.SenderProtocolAddr[:], []byte{10, byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
	copy(arp.TargetHardwareAddr[:], []byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
	copy(arp.TargetProtocolAddr[:], []byte{10, byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})

	eth := internal.ETH{
		Header:         &internal.ETH_HEADER{},
		Trailer:        &internal.ETH_TRAILER{},
		Inner:          arp,
		Inner_Protocol: internal.ARP,
	}
	copy(eth.Header.S_MAC[:], []byte{0x02, byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
	copy(eth.Header.D_MAC[:], []byte{0x02, byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
	putUint16(&eth.Header.ETH_TYPE, demoETHARP)
	return eth
}

func SniffLoop() {
	startPacketWorker()

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(uint16(syscall.ETH_P_ALL))))

	if err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	buffer := make([]byte, 65536)
	for {
		// we lose address in udp case switch to recvfrom
		n_bytes, err := syscall.Read(fd, buffer)

		if err != nil {
			//fmt.Printf("err: %s\n", err)
			continue
		}
		pkt := make([]byte, n_bytes)
		copy(pkt, buffer[:n_bytes])
		eth, err := internal.ParseEth(&pkt, &n_bytes)

		if err != nil {
			//fmt.Printf("err: %s\n", err)
			continue
		}

		pushPacket(eth)

	}
}

func DemoSniffLoop() {
	startPacketWorker()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	tcpFlows := []demoFlow{
		{srcMAC: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x11}, dstMAC: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x12}, srcIP: []byte{10, 0, 0, 10}, dstIP: []byte{10, 0, 0, 20}, srcPort: 12000, dstPort: 80, ipVersion: internal.IPV4, nextSeq: 1},
		{srcMAC: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x21}, dstMAC: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x22}, srcIP: []byte{192, 168, 1, 15}, dstIP: []byte{93, 184, 216, 34}, srcPort: 54000, dstPort: 443, ipVersion: internal.IPV4, nextSeq: 1000},
		{srcMAC: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x31}, dstMAC: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x32}, srcIP: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x10}, dstIP: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x20}, srcPort: 55000, dstPort: 443, ipVersion: internal.IPV6, nextSeq: 5000},
	}

	udpFlows := []demoFlow{
		{srcMAC: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x41}, dstMAC: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x42}, srcIP: []byte{10, 0, 0, 30}, dstIP: []byte{10, 0, 0, 40}, srcPort: 5353, dstPort: 5353, ipVersion: internal.IPV4},
		{srcMAC: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x51}, dstMAC: [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x52}, srcIP: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x30}, dstIP: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x40}, srcPort: 60000, dstPort: 53, ipVersion: internal.IPV6},
	}

	for {
		<-ticker.C
		switch rng.Intn(5) {
		case 0:
			flow := &tcpFlows[rng.Intn(len(tcpFlows))]
			eth, tcp := newDemoTCPPacket(rng, flow)
			pushPacket(eth)
			internal.PassTCP(tcp)
		case 1:
			flow := &tcpFlows[rng.Intn(len(tcpFlows))]
			eth, tcp := newDemoTCPPacket(rng, flow)
			pushPacket(eth)
			internal.PassTCP(tcp)
		case 2:
			flow := &udpFlows[rng.Intn(len(udpFlows))]
			pushPacket(newDemoUDPPacket(rng, flow))
		case 3:
			flow := &udpFlows[rng.Intn(len(udpFlows))]
			pushPacket(newDemoUDPPacket(rng, flow))
		default:
			pushPacket(newDemoARPPacket(rng))
		}
	}
}
