// usage : sudo ./main --mask --demo
// args : --mask : hides ip, port
//		  --demo : fake network data
package main

import (
	"packet_sniffer/cli"
	"flag"
	// "packet_sniffer/tests"
)

func main(){

	// tests.DebugRun()

	mask := flag.Bool("mask", false, "mask Mac Ip Port addresses")
	demo := flag.Bool("demo", false, "use synthetic demo packets instead of live capture")
	flag.Parse()

	cli.Tui(*mask, *demo)
}

