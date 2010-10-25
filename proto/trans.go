package proto

import (
    "os"
    "io"
    "encoding/binary"
)

const (
    IP_TCP = 6
    IP_UDP = 17

    TCP_FIN = 1 << iota
    TCP_SYN
    TCP_RST
    TCP_PSH
    TCP_ACK
    TCP_URG
)

type TCPFix struct {
    SrcPort  uint16
    DstPort  uint16
    SeqNum   uint32
    AckNum   uint32
    OffFlag  uint16
    Window   uint16
    Checksum uint16
    Urgent   uint16
}

type TCP struct {
	*TCPFix
	Options []byte
	OOB []byte
}

type UDP struct {
    SrcPort  uint16
    DstPort  uint16
	Length   uint16
	Checksum uint16
}

func (p *Protocol) DecodeTrans() os.Error {
	switch p.TransType {
	case IP_TCP:
		return p.DecodeTcp()
	case IP_UDP:
		return p.DecodeUdp()
	}
	
    return os.NewError("unkown transport type")
}

func (p *Protocol) DecodeTcp() os.Error {
	tcp := new(TCPFix)
	err := binary.Read(p.reader, binary.BigEndian, tcp)
	if err != nil {
		return os.NewError("read tcp header - " + err.String())
	}

    var options, oob []byte
	const MinLen = 20
	offset := (tcp.OffFlag & 0xF000) >> 10
    if offset < MinLen {
        return os.NewError("bad tcp offset")
    }

	if offset > MinLen {
        options = make([]byte, offset - MinLen)
        _, err := io.ReadFull(p.reader, options)
        if err != nil {
            return os.NewError("read tcp options - " + err.String())
        }
    }

	p.Length -= uint(offset)
	if tcp.OffFlag & TCP_URG > 0 {
		urgLen := tcp.Urgent + 8 - offset
		if urgLen <= 0 {
			return os.NewError("bad urgent length")
		}

		oob = make([]byte, urgLen)
        _, err := io.ReadFull(p.reader, oob)
        if err != nil {
            return os.NewError("read tcp oob - " + err.String())
        }

		p.Length -= uint(urgLen)
	}

	p.Trans = &TCP{tcp, options, oob}
	return nil
}

func (p *Protocol) DecodeUdp() os.Error {
	udp := new(UDP)
	err := binary.Read(p.reader, binary.BigEndian, udp)
	if err != nil {
		return os.NewError("read udp header - " + err.String())
	}

	p.Length = uint(udp.Length) - 8
	return nil
}
