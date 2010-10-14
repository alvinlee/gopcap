package proto

import (
	"os"
	// "io"
	// "encoding/binary"
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

type TCP struct {
	SrcPort uint16
	DstPort uint16
	SeqNum uint32
	AckNum uint32
	OffFlag uint16
	Window uint16
	Checksum uint16
	Urgent uint16
}

func (d *Decoder) DecodeTrans() (interface{}, os.Error) {
	return nil, nil
}

// func DecodeTcp(r io.Reader) (*Tcp, os.Error) {
// 	tcp := new(TCP)
// 	ret := binary.Read(r, binary.BigEndian, tcp)
// 	if ret != nil {
// 		return nil, ret
// 	}


	
// 	tcp.SrcPort = binary.BigEndian.Uint16(tcp.Body[0:2])
// 	tcp.DstPort = binary.BigEndian.Uint16(tcp.Body[2:4])
// 	tcp.Seq = binary.BigEndian.Uint32(tcp.Body[4:8])
// 	tcp.Ack = binary.BigEndian.Uint32(tcp.Body[8:12])
// 	offset := (uint8(tcp.Body[12]) & 0xF0) >> 4
// 	tcp.Flags = uint8(tcp.Body[13])
// 	tcp.Window = binary.BigEndian.Uint16(tcp.Body[14:16])
// 	tcp.Body = tcp.Body[offset:]
// 	return nil
// }

// func (udp *Udp) Decode() os.Error {
// 	udp.SrcPort = binary.BigEndian.Uint16(udp.Body[0:2])
// 	udp.DstPort = binary.BigEndian.Uint16(udp.Body[2:4])
// 	length := binary.BigEndian.Uint16(udp.Body[4:6])
// 	if length < 8 && int(length) > len(udp.Body) {
// 		return os.NewError("bad udp length")
// 	}
	
// 	udp.Body = udp.Body[8:length]
// 	return nil
// }

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


