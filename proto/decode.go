package proto

import (
	"io"
	"os"
)

type Decoder struct {
	reader io.Reader
	LinkType uint
	NetType uint
	TransType uint
	Length uint
}

type Protocol struct {
	Link interface{}
	Net interface{}
	Trans interface{}
}

func NewDecoder(t uint, r io.Reader) *Decoder {
	return &Decoder{reader:r, LinkType:t}
}

func (d *Decoder) Decode() (p *Protocol, e os.Error) {
	var link, net, trans interface{}
	link, e = d.DecodeLink()
	if e != nil {
		return 
	}

	net, e = d.DecodeNet()
	if e != nil {
		return 
	}

	trans, e = d.DecodeTrans()
	if e != nil {
		return 
	}

	p = &Protocol{link, net, trans}
	return
}
