// Layer 4 protocols types and parsing

package internal

import (
	"encoding/binary"
	"fmt"
)

// add flags for tcp

type TCP struct{
	Source_port [2]byte
	Dest_port [2]byte
	Sequence_number [4]byte
	Acknowledge_number [4]byte
	Data_offset byte
	Resereved byte
	Control_flags uint16 // track flags for description
	Window_size [2]byte
	Check_sum [2]byte
	Urgent_pointer [2]byte
	Options []byte
	Data []byte
}

type UDP struct{
	Source_ip byte
	Dest_ip byte
}

func ParseTCP(buffer *[]byte) (TCP, error){

	tcp := TCP{}

	copy(tcp.Source_port[:], (*buffer)[0:2])
	copy(tcp.Dest_port[:], (*buffer)[2:4])
	copy(tcp.Sequence_number[:], (*buffer)[4:8])
	copy(tcp.Acknowledge_number[:], (*buffer)[8:12])
	DRF := binary.BigEndian.Uint16((*buffer)[12:14]) // Data offset & Reserved & Flags

	data_offset := uint8((DRF & 0xF000) >> 12)
	reserved := uint8((DRF & 0x0E00) >> 9)
	flags := DRF & 0x01FF

	tcp.Data_offset = data_offset
	tcp.Resereved = reserved
	tcp.Control_flags= flags

	copy(tcp.Window_size[:], (*buffer)[14:16])
	copy(tcp.Check_sum[:], (*buffer)[16:18])
	copy(tcp.Urgent_pointer[:], (*buffer)[18:20])
	
	totalHeaderSize := int(data_offset) * 4
	// copy options only if data offset index > 5 bytes
	if data_offset > 5 {
		tcp.Options = (*buffer)[20:totalHeaderSize]
	}

	tcp.Data= (*buffer)[totalHeaderSize:]

	PrintTCP(&tcp, false)

	return tcp, nil
}

func PrintTCP(tcp *TCP, mask bool){
	var sIP []byte
	if mask{
		sIP = []byte{0,0}
	}else{
		sIP = tcp.Source_port[:]
	}

	fmt.Printf(`
Source_port: %x
Dest_port: %x
Sequence_number: %x
Acknowledge_number: %x
Data_offset: %x
Resereved: %x
Control_flags: %x
Window_size: %x
Check_sum: %x
Urgent_pointer: %x
Options: %x
Data: %x

`,
	sIP, 
	tcp.Dest_port, 
	tcp.Sequence_number,
	tcp.Acknowledge_number,
	tcp.Data_offset,
	tcp.Resereved,
	tcp.Control_flags,
	tcp.Window_size,
	tcp.Check_sum,
	tcp.Urgent_pointer,
	tcp.Options,
	tcp .Data,
)
}