package pcap

/*
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
*/
import "C"
import (
    "unsafe"
    "os"
)

const (
    ERRBUF_SIZE = C.PCAP_ERRBUF_SIZE
)

type Pcap struct {
    cptr *C.pcap_t
}

type Packet struct {
    Time struct {
        Sec  int32
        Usec int32
    }
    Caplen uint32
    Len    uint32
    Data   []byte
}

type Stats struct {
    Received  uint32
    Dropped   uint32
    IfDropped uint32
}

type Interface struct {
    Name        string
    Desc string
    // TODO: add more elements
}

func Openlive(dev string, snaplen int32, promisc bool, timeout int32) (ret *Pcap, msg string) {
    cdev := C.CString(dev)
    defer C.free(unsafe.Pointer(cdev))

    var cpro C.int
    if promisc {
        cpro = 1
    }

    var buf [ERRBUF_SIZE]byte
    cbuf := (*C.char)(unsafe.Pointer(&buf[0]))
    cptr := C.pcap_open_live(cdev, C.int(snaplen), C.int(cpro), C.int(timeout), cbuf)
    clen := C.strlen(cbuf)
    msg = string(buf[:clen])
    if cptr != nil {
        ret = &Pcap{cptr: cptr}
    }

    return
}

func Openoffline(file string) (ret *Pcap, msg string) {
    cfile := C.CString(file)
    defer C.free(unsafe.Pointer(cfile))

    var buf [ERRBUF_SIZE]byte
    cbuf := (*C.char)(unsafe.Pointer(&buf[0]))
    cptr := C.pcap_open_offline(cfile, cbuf)
    clen := C.strlen(cbuf)
    msg = string(buf[:clen])
    if cptr != nil {
        ret = &Pcap{cptr: cptr}
    }

    return
}

func (p *Pcap) Next() (*Packet, os.Error) {
    var header *C.struct_pcap_pkthdr
    var buf *C.u_char
    switch C.pcap_next_ex(p.cptr, &header, &buf) {
    case 0:
        return nil, os.NewError("read time out")
    case -1:
        return nil, os.NewError(p.Geterror())
    case -2:
        return nil, os.NewError("savefile eof")
    }

    ret := new(Packet)
    ret.Time.Sec = int32(header.ts.tv_sec)
    ret.Time.Usec = int32(header.ts.tv_usec)
    ret.Caplen = uint32(header.caplen)
    ret.Len = uint32(header.len)
    ret.Data = make([]byte, header.caplen)

    if header.caplen > 0 {
        C.memcpy(unsafe.Pointer(&ret.Data[0]), unsafe.Pointer(buf), C.size_t(header.caplen))
    }

    return ret, nil
}

func (p *Pcap) Geterror() string {
    return C.GoString(C.pcap_geterr(p.cptr))
}

func (p *Pcap) Getstats() (stats *Stats) {
    var cstats C.struct_pcap_stat
	if C.pcap_stats(p.cptr, &cstats) == -1 {
		return
	}

    stats = new(Stats)
    stats.Received = uint32(cstats.ps_recv)
    stats.Dropped = uint32(cstats.ps_drop)
    stats.IfDropped = uint32(cstats.ps_ifdrop)

    return
}

func (p *Pcap) Setfilter(expr string) os.Error {
    var bpf C.struct_bpf_program
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	if C.pcap_compile(p.cptr, &bpf, cexpr, 1, 0) == -1 {
        return os.NewError(p.Geterror())
    }
	defer C.pcap_freecode(&bpf)

    if C.pcap_setfilter(p.cptr, &bpf) == -1 {
		return os.NewError(p.Geterror())
    }

    return nil
}

func (p *Pcap) Datalink() int {
    return int(C.pcap_datalink(p.cptr))
}

func (p *Pcap) Setdatalink(dlt int) (err os.Error) {
    if C.pcap_set_datalink(p.cptr, C.int(dlt)) == -1 {
		err = os.NewError(p.Geterror())
    }
    return
}

func Version() string {
    return C.GoString(C.pcap_lib_version())
}

func DatalinkName(dlt int) (ret string) {
    name := C.pcap_datalink_val_to_name(C.int(dlt))
    if name != nil {
        ret = C.GoString(name)
    }
    return
}

func DatalinkDesc(dlt int) (ret string) {
    desc := C.pcap_datalink_val_to_description(C.int(dlt))
    if desc != nil {
        ret = C.GoString(desc)
    }
    return
}

func Findalldevs() (ifs []Interface, err os.Error) {
    var alldevsp *C.pcap_if_t
    var buf [ERRBUF_SIZE]byte
    cbuf := (*C.char)(unsafe.Pointer(&buf[0]))
	
    if C.pcap_findalldevs(&alldevsp, cbuf) == -1 {
		clen := C.strlen(cbuf)
		err = os.NewError(string(buf[:clen]))
		return 
    }
	defer C.pcap_freealldevs(alldevsp)

    dev := (*C.struct_pcap_if)(alldevsp)
	i := 0
    for ; dev != nil; dev = dev.next {
		i++
	}
	
    ifs = make([]Interface, i)
    for ; dev != nil; dev = dev.next {
		ifs[i].Name = C.GoString(dev.name)
		ifs[i].Desc = C.GoString(dev.description)
		i++
	}
	
    return
}

func (p *Pcap) Inject(data []byte) (err os.Error) {
    if C.pcap_inject(p.cptr, unsafe.Pointer(&data[0]),
		(C.size_t)(len(data))) == -1 {
        err = os.NewError(p.Geterror())
    }

    return
}
