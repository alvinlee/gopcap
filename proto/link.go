package proto

import (
    "os"
    "encoding/binary"
)

const (
    // according to pcap-linktype(7)
    LINKTYPE_NULL             = 0
    LINKTYPE_ETHERNET         = 1
    LINKTYPE_TOKEN_RING       = 6
    LINKTYPE_ARCNET           = 7
    LINKTYPE_SLIP             = 8
    LINKTYPE_PPP              = 9
    LINKTYPE_FDDI             = 10
    LINKTYPE_ATM_RFC1483      = 100
    LINKTYPE_RAW              = 101
    LINKTYPE_PPP_HDLC         = 50
    LINKTYPE_PPP_ETHER        = 51
    LINKTYPE_C_HDLC           = 104
    LINKTYPE_IEEE802_11       = 105
    LINKTYPE_FRELAY           = 107
    LINKTYPE_LOOP             = 108
    LINKTYPE_LINUX_SLL        = 113
    LINKTYPE_LTALK            = 104
    LINKTYPE_PFLOG            = 117
    LINKTYPE_PRISM_HEADER     = 119
    LINKTYPE_IP_OVER_FC       = 122
    LINKTYPE_SUNATM           = 123
    LINKTYPE_IEEE802_11_RADIO = 127
    LINKTYPE_ARCNET_LINUX     = 129
    LINKTYPE_LINUX_IRDA       = 144
    LINKTYPE_LINUX_LAPD       = 177

    LINUX_SLL_HOST      = 0
    LINUX_SLL_BROADCAST = 1
    LINUX_SLL_MULTICAST = 2
    LINUX_SLL_OTHERHOST = 3
    LINUX_SLL_OUTGOING  = 4
)

type LINK_ETHERNET struct {
    SrcMac  [6]byte
    DstMac  [6]byte
    NetType uint16
}

type LINK_LINUX_SLL struct {
    Ptype   uint16
    Atype   uint16
    Alen    uint16
    Addr    [8]byte
    NetType uint16
}

func (d *Decoder) DecodeLink() (interface{}, os.Error) {
    switch d.LinkType {
    case LINKTYPE_ETHERNET:
        eth := new(LINK_ETHERNET)
        err := binary.Read(d.reader, binary.BigEndian, eth)
        if err != nil {
            return nil, err
        }

        d.NetType = uint(eth.NetType)
        return eth, nil

    case LINKTYPE_LINUX_SLL:
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
