package cli

import (
	"fmt"
	"packet_sniffer/internal"
	"sync"
	"syscall"
)

func htons(x uint16) uint16 {
	return (x >> 8) | (x << 8)
}
var PacketMutex sync.Mutex
var Notify = make(chan int, 8192)
var Packet []internal.ETH

func SniffLoop() {

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(uint16(syscall.ETH_P_ALL))))

	if err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	go internal.PacketWorker()
	go internal.TriggerPrintTcpBucket()

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

		PacketMutex.Lock()
		Packet = append(Packet, eth)
		idx := len(Packet)-1
		PacketMutex.Unlock()
		select {
		case Notify <- idx:
		default:
		}

	}
}
