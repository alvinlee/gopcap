package proto

import (
    "io"
    "os"
)

type Protocol struct {
    reader    io.Reader
    LinkType  int
    NetType   uint
    TransType uint
    Length    uint
    Link  interface{}
    Net   interface{}
    Trans interface{}
}

func Decode(t int, r io.Reader) (*Protocol, os.Error) {
	p := &Protocol{reader: r, LinkType: t}
    return p, p.Decode()
}
 
func (p *Protocol) Decode() (e os.Error) {
	e = p.DecodeLink()
    if e != nil {
        return
    }

	e = p.DecodeNet()
    if e != nil {
        return
    }

    e = p.DecodeTrans()
    if e != nil {
        return
    }

    return
}
