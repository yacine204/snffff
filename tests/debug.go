package tests

import (
	"syscall"
	"packet_sniffer/internal"
	"fmt"
)


func htons(x uint16) uint16 {
	return (x >> 8) | (x << 8)
}

func DebugRun() {

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons((uint16(syscall.ETH_P_ALL)))))

	if err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	go internal.PacketWorker()
	go internal.TriggerPrintReassembledTcpBucket()

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
		_, err = internal.ParseEth(&pkt, &n_bytes)
		
		if err != nil {
			//fmt.Printf("err: %s\n", err)
			continue
		}

		// internal.PrintEth(eth)
		// eth.Inner.PrintL3(false)

	}


}

