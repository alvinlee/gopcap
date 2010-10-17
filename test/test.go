package main

import (
	"pcap"
	"fmt"
	"flag"
	"time"
)

func min(x uint32, y uint32) uint32 {
	if x < y {
		return x
	}
	return y
}

func main() {
	var device *string = flag.String("d", "", "device")
	var file *string = flag.String("r", "", "file")
	var expr *string = flag.String("e", "", "filter expression")

	flag.Parse()
	
	var h *pcap.Pcap

	ifs, err := pcap.Findalldevs()
	if len(ifs) == 0 {
		fmt.Printf("Warning: no devices found : %s\n", err)
	} else {
		for i := 0 ; i < len(ifs) ; i++ {
			fmt.Printf("dev %d: %s (%s)\n", i+1, ifs[i].Name, ifs[i].Desc)
		}
	}

	var msg string
	if *device != "" {
		h, msg = pcap.Openlive(*device, 65535, true, 0)
	} else if *file != "" {
		h, msg = pcap.Openoffline(*file)
	} else {
		fmt.Printf("usage: pcaptest [-d <device> | -r <file>]\n")
		return
	}

	if msg != "" {
		fmt.Printf("Open (%s%s) failed: %s\n", *device, *file, msg)
	}

	if h == nil {
		return
	}

	fmt.Printf("pcap version: %s\n", pcap.Version())

	if *expr != "" {
		fmt.Printf("Setting filter: %s\n", *expr)
		err := h.Setfilter(*expr)
		if err != nil {
			fmt.Printf("Warning: setting filter failed: %s\n", err)
		}
	}

	for {
		pkt, err := h.Next()
		if err != nil {
			fmt.Println("capture:", err)
		}

		if pkt == nil {
			continue
		}
		
		fmt.Printf("time: %d.%06d (%s) caplen: %d len: %d\nData:", 
			int64(pkt.Time.Sec), int64(pkt.Time.Usec), 
			time.SecondsToLocalTime(int64(pkt.Time.Sec)).String(), int64(pkt.Caplen), int64(pkt.Len))

		for i:=uint32(0) ; i<pkt.Caplen ; i++ {
			if i % 32 == 0 {
				fmt.Printf("\n")
			}
			if 32 <= pkt.Data[i] && pkt.Data[i] <= 126 {
				fmt.Printf("%c", pkt.Data[i])
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Printf("\n\n")
	}

}
