# snffff

Tui packet sniffer using unix raw sockets, supports TCP reassembly and regrouping.

## What it does 

- Intercepts ethernet packets using `AF_PACKET` sockets
- parses layer 2-4 from osi
- grouping/reassembling tcp packets by flowId
- filter packets by flowId (srcIp+srcPort+dstIp+dstPort)

<video controls muted loop playsinline width="100%" poster="assets/demo.png">
	<source src="assets/demo.mp4" type="video/mp4">
</video>

## Installation (works only on unix systems)

```bash 
git clone https://github.com/yacine204/snffff
cd snffff
go build -o main main.go
sudo ./main --mask --demo # raw sockets requires root priviliges 
```
