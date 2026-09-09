package internal


type IPV4_H struct {
	Version uint8
	IHL uint8
	TOS uint8
	TotalLength uint16
	Indent uint16
	Flags uint8
	FragOffset uint16
	TTL uint8
	Protocol uint8
	HeaderCS uint16
	SourceAddr [4]byte
	DestAddr [4]byte
	Options [40]byte 
	Data []byte 
}	

type IPV6_H struct {
	Version uint8 
	TrafficClass uint8
	FlowLabel uint16
	PayloadLen uint16
	NextHeader uint8
	HopLimit uint8
	SourceAddr [16]byte
	DestAddr [16]byte
	Data []byte
}



type IP4 struct{
	Header *IPV4_H
	Payload []byte
}

type IP6 struct{
	Header *IPV6_H
	Payload []byte
}