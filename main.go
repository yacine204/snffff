// intercept copies of packets (keep Layer 2 for confirmation since it has mac)
// workflow: parse the raw bytes to structured .csv 
// 			?keep scanning and log to the terminal directly

package main

import 
(	
	"syscall"
	"fmt"
	"packet_sniffer/internal"
)

// shift left side of 16 bit integer to the right
func htons(x uint16) uint16{
	return (x >> 8) | (x<<8) 
}

func main (){
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(uint16(syscall.ETH_P_ALL))))

	if err!=nil{
		fmt.Printf("err: %s\n", err)
	}

	buffer := make([]byte, 1024)
	for {
		// we lose address in udp case switch to recvfrom
		n_bytes, err := syscall.Read(fd, buffer)

		if err!=nil{
			fmt.Printf("err: %s\n", err)
		}	
		_, err = internal.ParseEth(&buffer, &n_bytes)

		if err!=nil{
			fmt.Printf("err: %s\n", err)
		}
		// internal.PrintEth(eth_packet)
		//fmt.Printf("read %d bytes, raw bytes:\n%x\n", n_bytes, buffer[:n_bytes])
	}
}