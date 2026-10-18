# snffff

Tui packet sniffer using unix raw sockets, supports TCP reassembly and regrouping.

## What it does 

- Intercepts ethernet packets using `AF_PACKET` sockets
- parses layer 2-4 from osi
- grouping/reassembling tcp packets by flowId
- filter packets by flowId (srcIp+srcPort+dstIp+dstPort)

![](assets/demo.mp4)

## Installation (works only on unix systems)

```bash 
git clone https://github.com/yacine204/snffff
cd snffff
go build -o main main.go
sudo ./main --mask --demo # raw sockets requires root priviliges 
```
