// intercept copies of packets (keep Layer 2 for confirmation since it has mac)
// workflow: parse the raw bytes to structured .csv
// 			?keep scanning and log to the terminal directly

// args: 
//		-mask
//		-nework interface 
package main

import (
	"packet_sniffer/cli"
	"os"
	// "packet_sniffer/tests"
)

func main(){

	// tests.DebugRun()


	mask := os.Args[1]
	// network_interface := os.Args[2]
	var masked bool
	if mask == "masked"{
		masked = true
	}
	cli.Tui(masked)
}

