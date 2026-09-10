# snffff

Minimal packet sniffer using unix syscalls and byte parsing

## What it does 

- Intercepts ethernet packets using `AF_PACKET`  sockets
- parses layer 2 and 3 from osi

output sample: 
```bash
Version: 4
IHL: 5
TOS: 0
Total length: 0088
Identification: 2330
Flags: 0
Fragment offset: 0
TTL: 40
Protocol: 17
Header checksum: 958a
Source Addr: 00000000 #masked
Dest Addr: ffffffff
Options: 
Data: c000650400744fb...000000

D_Mac: ffffffffffff
S_Mac: ffffffffffff #masked
V_tag: 00000000
Eth_type: 0800
Payload: 450000882330000...000000
```

## Installation (works only on unix systems)

```bash 
git clone https://github.com/yacine204/snffff
cd snffff
go build -o main main.go
sudo ./main # raw sockets requires root priviliges 
```
