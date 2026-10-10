// intercept copies of packets (keep Layer 2 for confirmation since it has mac)
// workflow: parse the raw bytes to structured .csv
// 			?keep scanning and log to the terminal directly

package main

import (
	"packet_sniffer/cli"
)

func main(){
	cli.Tui()
}

