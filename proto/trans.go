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

func (d *Decoder) DecodeTrans() (interface{}, os.Error) {
	switch d.TransType {
	case IP_TCP:
		return d.DecodeTcp()
	case IP_UDP:
		return d.DecodeUdp()
	}
	
    return nil, os.NewError("unkown transport type")
}

func (d *Decoder) DecodeTcp() (*TCP, os.Error) {
	tcp := new(TCPFix)
	ret := binary.Read(d.reader, binary.BigEndian, tcp)
	if ret != nil {
		return nil, ret
	}

    var options, oob []byte
	const MinLen = 20
	offset := (tcp.OffFlag & 0xF000) >> 10
    if offset < MinLen {
        return nil, os.NewError("bad tcp offset")
    }

	if offset > MinLen {
        options = make([]byte, offset - MinLen)
        _, ret := io.ReadFull(d.reader, options)
        if ret != nil {
            return nil, ret
        }
    }

	d.Length -= uint(offset)

	if tcp.OffFlag & TCP_URG > 0 {
		urgLen := tcp.Urgent + 8 - offset
		if urgLen <= 0 {
			return nil, os.NewError("bad urgent length")
		}

		oob = make([]byte, urgLen)
        _, ret := io.ReadFull(d.reader, oob)
        if ret != nil {
            return nil, ret
        }

		d.Length -= uint(urgLen)
	}

	return &TCP{tcp, options, oob}, nil
}

func (d *Decoder) DecodeUdp() (udp *UDP, err os.Error) {
	udp = new(UDP)
	err = binary.Read(d.reader, binary.BigEndian, udp)
	if err != nil {
		return
	}

	d.Length = uint(udp.Length) - 8
	return
}

// func (tcp *Tcp) String() string {
// 	return fmt.Sprintf("TCP %v:%d -> %v:%d %d %d %d %b \t%x", tcp.Src, tcp.SrcPort,
// 		tcp.Dst, tcp.DstPort, tcp.Seq, tcp.Ack, tcp.Window, tcp.Flags, stripStr(tcp.Body))
// }

// func (udp *Udp) String() string {
// 	return fmt.Sprintf("UDP %v:%d -> %v:%d \t%x", udp.Src, udp.SrcPort,
// 		udp.Dst, udp.DstPort, stripStr(udp.Body))
// }

// func stripStr(buf []byte) []byte{
// 	const max = 20
// 	cur := len(buf)
// 	if cur > max {
// 		return buf[:max]
// 	}

// 	return buf
// }
