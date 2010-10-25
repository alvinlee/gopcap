package proto

import (
    "os"
    "io"
    "encoding/binary"
)

const (
    NET_IP4 = 0x0800
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

func (p *Protocol) DecodeNet() os.Error {
    switch p.NetType {
    case NET_IP4:
        return p.DecodeIPv4()
    }

    return os.NewError("unkown network type")
}

func (p *Protocol) DecodeIPv4() os.Error {
    ip := new(IPv4Fix)
    err := binary.Read(p.reader, binary.BigEndian, ip)
    if err != nil {
        return os.NewError("read ip header - " + err.String())
    }

    ver := ip.VerHL >> 4
    if ver != 4 {
        return os.NewError("not ip v4")
    }
	
    var options []byte
	const MinLen = 20
	offset := uint16((ip.VerHL & 0x0F) * 4)
    if offset < MinLen || ip.Length < offset {
        return os.NewError("bad ip v4 length")
    }

	if offset > MinLen {
        options = make([]byte, offset - MinLen)
        _, err := io.ReadFull(p.reader, options)
        if err != nil {
            return os.NewError("read ip options - " + err.String())
        }
    }

	p.TransType = uint(ip.Protocol)
	p.Length = uint(ip.Length - offset)
	p.Net = &IPv4{ip, options}
    return nil
}
