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
	Payload	any // keep any since we dont know what we get as a payload
	Trailer *ETH_TRAILER
}

func reallocPayloadSize(packet *ETH) (bool, Alloc, error){
	// allocate ETH payload type or size from ETHERTYPE value
	ETH_TYPE_uint16 := binary.BigEndian.Uint16(packet.Header.ETH_TYPE[:])
	if ETH_TYPE_uint16 >= 1536 {
		switch ETH_TYPE_uint16{
		case uint16(ETH_IPV4):
			packet.Payload = IP4{}
			return true, Alloc{Type: ETH_IPV4, Size: ETH_IPV4_SIZE} ,nil
		case uint16(ETH_IPV6):
			packet.Payload = IP6{}
			return true, Alloc{Type: ETH_IPV6, Size: ETH_IPV6_SIZE} ,nil
		// todo : add ARP, ...
		default:
			return false, Alloc{}, fmt.Errorf("unrecognized ETHERTYPE: %d\n", packet.Header.ETH_TYPE)
		}
	}else{
		packet.Payload = make([]byte, ETH_TYPE_uint16)
		return false, Alloc{}, nil
	}
	
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
		// _, alloc, _ := reallocPayloadSize(&eth)
		//copy(eth.Trailer.FCS[:], (*buffer)[18+alloc.Size:])
		eth.Payload = (*buffer)[18:]
	}else{
		copy(eth.Header.ETH_TYPE[:], (*buffer)[12:14])
		// _, alloc, _ := reallocPayloadSize(&eth)
		// copy(eth.Trailer.FCS[:], (*buffer)[14+alloc.Size:])
		eth.Payload = (*buffer)[14:]
	}
	
	payloadBytes := eth.Payload.([]byte)

	L4Parser(&payloadBytes)

	return eth, nil
}

func PrintEth(eth ETH){ 
	fmt.Printf(
		"D_Mac: %x\nS_Mac: %x\nV_tag: %x\nEth_type: %x\nPayload: %x\n",
		eth.Header.D_MAC[:], eth.Header.S_MAC[:], eth.Header.V_TAG[:] ,eth.Header.ETH_TYPE[:], eth.Payload)
}