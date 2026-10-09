package internal

import (
	"encoding/binary"
	"fmt"
)

type ETH_TYPE uint

type ETH_TYPE_SIZE int

const (
	ETH_IPV4 ETH_TYPE = 0x0800
	ETH_IPV6 ETH_TYPE = 0x86DD
)

const (
	ETH_IPV4_SIZE ETH_TYPE_SIZE = 65575
	ETH_IPV6_SIZE ETH_TYPE_SIZE = 65535
)

type Alloc struct {
	Type ETH_TYPE
	Size ETH_TYPE_SIZE
}

type ETH_HEADER struct{
	S_MAC [6]byte
	D_MAC [6]byte
	V_TAG	[4]byte
	ETH_TYPE [2]byte
}

type ETH_TRAILER struct{
	FCS [4]byte
}

type ETH struct{
	Header *ETH_HEADER
	Payload	[]byte 
	Trailer *ETH_TRAILER
	Inner L3Capsule
	Inner_Protocol L3Protocols
}




func ParseEth(buffer *[]byte, n_bytes *int) (ETH, error){
	var eth = ETH{}

	eth.Header = &ETH_HEADER{}
	eth.Trailer = &ETH_TRAILER{}

	copy(eth.Header.D_MAC[:], (*buffer)[0:6])
	copy(eth.Header.S_MAC[:], (*buffer)[6:12])


	if binary.BigEndian.Uint16((*buffer)[12:14]) == 0x8100 ||  binary.BigEndian.Uint16((*buffer)[12:14])== 0x88A8 {
		copy(eth.Header.V_TAG[:], (*buffer)[12:16])
		copy(eth.Header.ETH_TYPE[:], (*buffer)[16:18])
		eth.Payload = (*buffer)[18:]
	}else{
		copy(eth.Header.ETH_TYPE[:], (*buffer)[12:14])
		eth.Payload = (*buffer)[14:]
	}
	
	payloadBytes := eth.Payload

	PrintEth(eth)

	capsule, protocol, err := L3Parser(&payloadBytes)

	if err!=nil{
		return ETH{}, err
	}

	eth.Inner = capsule
	eth.Inner_Protocol = protocol

	return eth, nil
}

func PrintEth(eth ETH){ 
	fmt.Printf(
		"D_Mac: %x\nS_Mac: %x\nV_tag: %x\nEth_type: %x\nPayload: %x\n\n",
		eth.Header.D_MAC[:], eth.Header.S_MAC[:], eth.Header.V_TAG[:] ,eth.Header.ETH_TYPE[:], eth.Payload)
}