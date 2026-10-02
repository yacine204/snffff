package internal

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"sync"
)

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

	// for tcp reassambly
	Source_ip []byte
	Dest_ip []byte

	IpVersion L3Protocols
}

type UDP struct{
	Source_ip byte
	Dest_ip byte
}


func GenerateFlowID(tcp *TCP) (string){
	srcIPStr := IpToString(tcp.Source_ip, tcp.IpVersion)
	dstIPStr := IpToString(tcp.Dest_ip, tcp.IpVersion)

	srcPort := binary.BigEndian.Uint16(tcp.Source_port[:])
	dstPort := binary.BigEndian.Uint16(tcp.Dest_port[:])

	return fmt.Sprintf("%s:%d-%s:%d", srcIPStr, srcPort, dstIPStr, dstPort)
}

var tcpBucket = make(map[string][]TCP)

var tcpBucketMutex sync.RWMutex

var PacketChan = make(chan TCP, 1000)

var PacketReassemblyTrigger = make(chan TCP, 1000)

func PassTCP(tcp *TCP){
	PacketChan <- *tcp
	PacketReassemblyTrigger <- *tcp
}

func GroupTcp(tcp *TCP){
	flowId := GenerateFlowID(tcp)
	tcpBucketMutex.Lock()
	tcpBucket[flowId] = append(tcpBucket[flowId], *tcp)
	tcpBucketMutex.Unlock()
}

func IpToString(ip []byte, version L3Protocols) string {
    if version == IPV4 {
        if len(ip) != 4 {
            return "?"
        }
        return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
    }
    if version == IPV6 {
        if len(ip) != 16 {
            return "?"
        }
        return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
            binary.BigEndian.Uint16(ip[0:2]),
            binary.BigEndian.Uint16(ip[2:4]),
            binary.BigEndian.Uint16(ip[4:6]),
            binary.BigEndian.Uint16(ip[6:8]),
            binary.BigEndian.Uint16(ip[8:10]),
            binary.BigEndian.Uint16(ip[10:12]),
            binary.BigEndian.Uint16(ip[12:14]),
            binary.BigEndian.Uint16(ip[14:16]),
        )
    }
    return ""
}

func getMaxAllocSizeForFlow(tcpArray []TCP) uint {
    if len(tcpArray) == 0 {
        return 0
    }
    isn := binary.BigEndian.Uint32(tcpArray[0].Sequence_number[:])
    for _, tcp := range tcpArray {
        seq := binary.BigEndian.Uint32(tcp.Sequence_number[:])
        if seq < isn {
            isn = seq
        }
    }
    var maxEnd uint32
    for _, tcp := range tcpArray {
        seq := binary.BigEndian.Uint32(tcp.Sequence_number[:])
        end := (seq - isn) + uint32(len(tcp.Data))
        if end > maxEnd {
            maxEnd = end
        }
    }
    return uint(maxEnd)
}


var ReassembledTcp = make(map[string][]byte)

var ReassembleTcpMutex sync.Mutex


func ReassembleTcpPerFlow(tcpBucket map[string][]TCP, flowId string){
	pkts := tcpBucket[flowId]

	if len(pkts) == 0 {
		return
	}
	isn := binary.BigEndian.Uint32(pkts[0].Sequence_number[:])

	for _, tcp := range pkts {
		seq := binary.BigEndian.Uint32(tcp.Sequence_number[:])
        if seq < isn {
            isn = seq
        }
	}

	allocsize := getMaxAllocSizeForFlow(tcpBucket[flowId])
	buf := make([]byte, allocsize)

	// mark sorted packets to not override
	sortedByPacket := make(map[int]bool)

	for i, tcp := range tcpBucket[flowId]{
		if sortedByPacket[i]{
			continue
		}
		seq := binary.BigEndian.Uint32(tcp.Sequence_number[:])
		off := int(seq-isn)
		if off < 0 || off+len(tcp.Data) > len(buf) {
			continue
		}
		copy(buf[off:], tcp.Data)
		sortedByPacket[i] = true
	}

	ReassembleTcpMutex.Lock()
	ReassembledTcp[flowId] = buf
	ReassembleTcpMutex.Unlock()
}


func PacketWorker() {
	for tcp := range PacketChan {
		local := tcp
		GroupTcp(&local)
		flowId := GenerateFlowID(&local)

		tcpBucketMutex.RLock()
		ReassembleTcpPerFlow(tcpBucket, flowId)
		tcpBucketMutex.RUnlock()
	}
}


func PrintGroupedTcpBucket(tcpBucket map[string][]TCP){
	// for each uid print the list of tcp's

	for fid, tcps := range tcpBucket{
		fmt.Printf("flow id %s :\n", fid)
		for _, tcp := range tcps{
			PrintTCP(&tcp, false)
		}
	}
}

func  PrintReassembledTcpBucket(reassembledTcpBucket map[string][]byte){
	for fid, tcp := range reassembledTcpBucket{
		fmt.Printf("flow id %s: \n% x\n", fid, tcp)
	}
}

func TriggerPrintTcpBucket(){
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	
	<-c

	tcpBucketMutex.RLock()
	ReassembleTcpMutex.Lock()
	// PrintGroupedTcpBucket(tcpBucket)
	PrintReassembledTcpBucket(ReassembledTcp)
	ReassembleTcpMutex.Unlock()
	tcpBucketMutex.RUnlock()

	os.Exit(0)
}

func ParseTCP(buffer *[]byte, srcIP []byte, destIp []byte, version L3Protocols) (TCP, error){

	tcp := TCP{}

	tcp.Source_ip = append([]byte(nil), srcIP...)
	tcp.Dest_ip = append([]byte(nil), destIp...)

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
		tcp.Options = append([]byte(nil), (*buffer)[20:totalHeaderSize]...)
	}
	tcp.IpVersion = version
	tcp.Data = append([]byte(nil), (*buffer)[totalHeaderSize:]...)

	PrintTCP(&tcp, false)

	PassTCP(&tcp)
	//GroupTcp(&tcp, GenerateFlowID(&tcp))

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