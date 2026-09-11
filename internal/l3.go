package internal

import (
	"encoding/binary"
	"fmt"
)

type L3Protocols string
const (
	IPV4 L3Protocols = "ipv4"
	IPV6 L3Protocols = "ipv6"
	ARP L3Protocols = "arp"
	UNKNOWN_TO_PARSER L3Protocols = ""
)

type IPV4_H struct {
	Version byte
	IHL uint8
	TOS uint8
	TotalLength [2]byte
	Indent [2]byte
	Flags uint8
	FragOffset uint16
	TTL uint8
	Protocol uint8
	HeaderCS [2]byte
	SourceAddr [4]byte
	DestAddr [4]byte
	Options []byte 
}	

type IPV6_H struct {
	Version byte 
	TrafficClass uint8
	FlowLabel uint32
	PayloadLen [2]byte
	NextHeader uint8
	HopLimit uint8
	SourceAddr [16]byte
	DestAddr [16]byte
}


type IP4 struct{
	Header *IPV4_H
	Payload []byte
}

type IP6 struct{
	Header *IPV6_H
	Payload []byte
}

type ARP_H struct{
	HardwareType [2]byte
	ProtocolType [2]byte // specify on this if we need to parse
	HardwareAddrLen byte 
	ProtocolAddrLen byte 
	Operation [2]byte // 1 -> request, 2 -> response
	SenderHardwareAddr [4]byte
	SenderProtocolAddr [4]byte
	TargetHardwareAddr [4]byte
	TargetProtocolAddr [4]byte
}

func CheckIpVersion(buffer *[]byte) (int){
	version := int((*buffer)[0] >> 4) 
	if version == 4 || version == 6{
		return version
	}
	return 0
}

func ParseIpv4(buffer *[]byte) (IP4, error){
	ipv4 := IP4{}
	ipv4.Header = &IPV4_H{}

	ipv4.Header.Version = (*buffer)[0] >> 4
	ipv4.Header.IHL = (*buffer)[0] & 0x0F

	ipv4.Header.TOS = (*buffer)[1]
	copy(ipv4.Header.TotalLength[:], (*buffer)[2:4])

	copy(ipv4.Header.Indent[:], (*buffer)[4:6])
	
	ipv4.Header.Flags = (*buffer)[6] >> 5
	flagsAndFragOffset := binary.BigEndian.Uint16((*buffer)[6:8])
	ipv4.Header.FragOffset = flagsAndFragOffset & 0x1FFF

	ipv4.Header.TTL = (*buffer)[8]
	ipv4.Header.Protocol = (*buffer)[9]

	copy(ipv4.Header.HeaderCS[:], (*buffer)[10:12])
	copy(ipv4.Header.SourceAddr[:], (*buffer)[12:16])
	copy(ipv4.Header.DestAddr[:], (*buffer)[16:20])
	

	if ipv4.Header.IHL == 5{
		ipv4.Payload = (*buffer)[20:]
	}else if ipv4.Header.IHL > 5{
		ipv4.Header.Options = (*buffer)[20:ipv4.Header.IHL*4]
		ipv4.Payload = (*buffer)[ipv4.Header.IHL*4:]
	}else{
		return IP4{}, fmt.Errorf("IHL header size not valid: %d\n",ipv4.Header.IHL)
	}

	// todo : move print outside of func
	PrintIPv4(&ipv4, true)

	return ipv4, nil
}

func ParseIpv6(buffer *[]byte) (IP6, error){
	var ipv6 = IP6{}
	ipv6.Header = &IPV6_H{}

	ipv6.Header.Version = (*buffer)[0]  >> 4
	trafficClass := ((*buffer)[0] & 0x0F ) << 4 | ((*buffer)[1] & 0xF0) >> 4
	ipv6.Header.TrafficClass = trafficClass

	flowLable := uint32((*buffer)[1]&0x0F)<<16 | uint32((*buffer)[2])<<8 | uint32((*buffer)[3])
	ipv6.Header.FlowLabel = uint32(flowLable)

	copy(ipv6.Header.PayloadLen[:], (*buffer)[4:6])
	ipv6.Header.NextHeader = (*buffer)[6]

	ipv6.Header.HopLimit = (*buffer)[7]
	copy(ipv6.Header.SourceAddr[:], (*buffer)[8:24])
	copy(ipv6.Header.DestAddr[:], (*buffer)[24:40])
	// todo : parse extension headers seperately in the payload
	ipv6.Payload = (*buffer)[40:]

	// todo : move print outside of func
	PrintIPv6(&ipv6, true)
	return ipv6, nil
}

func PrintIPv4(ipv4 *IP4, mask bool) {
    var srcIP []byte
    if mask {
        srcIP = []byte{0, 0, 0, 0}
    } else {
        srcIP = ipv4.Header.SourceAddr[:]
    }

    fmt.Printf(`Version: %x
IHL: %x
TOS: %x
Total length: %x
Identification: %x
Flags: %x
Fragment offset: %x
TTL: %x
Protocol: %d
Header checksum: %x
Source Addr: %x
Dest Addr: %x
Options: %x
Data: %x

`,
    ipv4.Header.Version,
    ipv4.Header.IHL,
    ipv4.Header.TOS,
    ipv4.Header.TotalLength,
    ipv4.Header.Indent,
    ipv4.Header.Flags,
    ipv4.Header.FragOffset,
    ipv4.Header.TTL,
    ipv4.Header.Protocol,
    ipv4.Header.HeaderCS,
    srcIP,
    ipv4.Header.DestAddr,
    ipv4.Header.Options,
    ipv4.Payload,
    )
}

func PrintIPv6(ipv6 *IP6, mask bool){
	var srcIP []byte
	if mask{
		srcIP = []byte{0,0,0,0}
	}else{
		srcIP = ipv6.Header.SourceAddr[:]
	}

	fmt.Printf(`Version: %x
Traffic Class: %x
Flow label: %x
Payload Length: %x
Next Header: %x
Hop Limit: %x
Source Addr: %x
Dest Addr: %x

`,
	ipv6.Header.Version,
	ipv6.Header.TrafficClass,
	ipv6.Header.FlowLabel,
	ipv6.Header.PayloadLen,
	ipv6.Header.NextHeader,
	ipv6.Header.HopLimit,
	srcIP,
	ipv6.Header.DestAddr,
)
}

func ParseARP(buffer *[]byte) (ARP_H, error){
	var arp = ARP_H{}

	if len(*buffer) < 28{
		return ARP_H{}, fmt.Errorf("arp: buffer too short: %d bytes", len(*buffer))
	}

	copy(arp.HardwareType[:], (*buffer)[0:2])
	copy(arp.ProtocolType[:], (*buffer)[2:4])
	arp.HardwareAddrLen = (*buffer)[4]
	arp.ProtocolAddrLen = (*buffer)[5]
	copy(arp.Operation[:], (*buffer)[6:8])

	operation := binary.BigEndian.Uint16(arp.Operation[:])

	if operation != 2 && operation != 1 {
		return ARP_H{}, fmt.Errorf("unknow arp operation: %d", len(*buffer))
	}

	copy(arp.SenderHardwareAddr[:], (*buffer)[8:14])
	copy(arp.SenderProtocolAddr[:], (*buffer)[14:18])
	copy(arp.TargetHardwareAddr[:], (*buffer)[18:24])
	copy(arp.TargetProtocolAddr[:], (*buffer)[24:28])

	PrintARP(&arp)
	return arp, nil
}

func PrintARP(arp *ARP_H){
	fmt.Printf(`
Hardware type: %x
Protocol type: %x
Hardware address len: %x
Protocol Address Length: %x
Operation: %x
Sender Hardware Address: %x
Sender Protocol Address: %x
Target Hardware Address: %x
Target Protocol Address: %x
`,
arp.HardwareType, 
arp.ProtocolType,
arp.HardwareAddrLen,
arp.ProtocolAddrLen,
arp.Operation,
arp.SenderHardwareAddr,
arp.SenderProtocolAddr,
arp.TargetHardwareAddr,
arp.TargetProtocolAddr,
)
}

func L4Parser(buffer *[]byte) (any, L3Protocols, error) {
	version := CheckIpVersion(buffer)
	validVersion := version == 4 || version == 6

	if (validVersion){
		switch version{
		case 4:
			ip4, err := ParseIpv4(buffer)
			return ip4, IPV4 ,err
		case 6:
			ip6, err := ParseIpv6(buffer)
			return ip6, IPV6 ,err
			
		default: 
			return nil, UNKNOWN_TO_PARSER, nil
		}
	}else{
		arp, err := ParseARP(buffer)
		return arp, ARP, err
	}
}