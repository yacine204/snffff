# snffff

Tui packet sniffer for linux, supports TCP reassembly and regrouping.

## Why

educational purposes only.

## What it does 

- Intercepts ethernet packets using `AF_PACKET` sockets
- parses OSI layers 2–4 (Ethernet, IPv4/IPv6/ARP, TCP/UDP)
- groups TCP segments into flows and reassembles them by sequence number
- filter packets by flowId (srcIp:srcPort:dstIp:dstPort)
  
## Demo

>note: demo using `--demo`, which means no real traffic network is captured or shown.

![demo](assets/demo.png)

https://github.com/user-attachments/assets/456196d7-7ca9-422b-819f-e038b94b4e45

## Installation (linux only)

```bash 
git clone https://github.com/yacine204/snffff
cd snffff
go build -o main main.go
sudo ./main --mask --demo # raw sockets requires root priviliges 
```
