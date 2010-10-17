package proto

import (
    "os"
    "io"
    "encoding/binary"
)

const (
    NET_IP  = 0x0800
    NET_ARP = 0x0806
    NET_IP6 = 0x86DD
)

type IPv4Fix struct {
    VerHL    uint8
    Tos      uint8
    Length   uint16
    Id       uint16
    Frag     uint16
    TTL      uint8
    Protocol uint8
    Checksum uint16
    Src      [4]byte
    Dst      [4]byte
}

type IPv4 struct {
    *IPv4Fix
    Options []byte
}

func (d *Decoder) DecodeNet() (interface{}, os.Error) {
    switch d.NetType {
    case NET_IP:
        return d.DecodeIPv4()
    }

    return nil, os.NewError("unkown network type")
}

func (d *Decoder) DecodeIPv4() (*IPv4, os.Error) {
    ip := new(IPv4Fix)
    ret := binary.Read(d.reader, binary.BigEndian, ip)
    if ret != nil {
        return nil, ret
    }

    ver := ip.VerHL >> 4
    if ver != 4 {
        return nil, os.NewError("not ip v4")
    }
	
    var options []byte
	const MinLen = 20
	offset := uint16((ip.VerHL & 0x0F) * 4)
    if offset < MinLen || ip.Length < offset {
        return nil, os.NewError("bad ip v4 length")
    }

	if offset > MinLen {
        options = make([]byte, offset - MinLen)
        _, ret := io.ReadFull(d.reader, options)
        if ret != nil {
            return nil, ret
        }
    }

	d.TransType = uint(ip.Protocol)
	d.Length = uint(ip.Length - offset)

    return &IPv4{ip, options}, nil
}
