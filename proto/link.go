package proto

import (
    "os"
	"pcap"
	"encoding/binary"
)

const (
    LINUX_SLL_HOST      = 0
    LINUX_SLL_BROADCAST = 1
    LINUX_SLL_MULTICAST = 2
    LINUX_SLL_OTHERHOST = 3
    LINUX_SLL_OUTGOING  = 4
)

type LINK_ETHERNET struct {
    SrcMac [6]byte
    DstMac [6]byte
    NetType uint16
}

type LINK_LINUX_SLL struct {
    Ptype uint16
    Atype uint16
    Alen  uint16
    Addr  [8]byte
    NetType uint16
}

func (d *Decoder) DecodeLink() (interface{}, os.Error) {
    switch d.LinkType {
    case pcap.LINKTYPE_ETHERNET:
		eth := new(LINK_ETHERNET)
		err := binary.Read(d.reader, binary.BigEndian, eth)
		if err != nil {
			return nil, err
		}

		d.NetType = uint(eth.NetType)
		return eth, nil
		
    case pcap.LINKTYPE_LINUX_SLL:
		sll := new(LINK_LINUX_SLL)
		err := binary.Read(d.reader, binary.BigEndian, sll)
		if err != nil {
			return nil, err
		}

		d.NetType = uint(sll.NetType)
		return sll, nil
    }
	
	return nil, os.NewError("unkown link type")
}
