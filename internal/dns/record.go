package dns

import (
	"fmt"
	"net/netip"
)

// Record is one resource record in the answer/authority/additional sections.
//
//	<name>            variable, length-prefixed labels (possibly compressed)
//	<type:u16>        DNS type code
//	<class:u16>       always 1 (IN)
//	<ttl:u32>         seconds the answer can be cached
//	<rdlength:u16>    length in bytes of the rdata that follows
//	<rdata>           variable, parsed per type
type Record struct {
	Domain  string
	Type    QueryType
	TTL     uint32
	DataLen uint16

	Addr     netip.Addr // A, AAAA
	Host     string     // NS, CNAME, MX (exchange host)
	Priority uint16     // MX
}

// Read pulls one resource record off the buffer.
func (r *Record) Read(buf *BytePacketBuffer) error {
	domain, err := buf.ReadQName()
	if err != nil {
		return err
	}
	r.Domain = domain

	t, err := buf.ReadU16()
	if err != nil {
		return err
	}
	r.Type = QueryType(t)

	// class — always 1 (IN), discard
	if _, err := buf.ReadU16(); err != nil {
		return err
	}

	ttl, err := buf.ReadU32()
	if err != nil {
		return err
	}
	r.TTL = ttl

	dataLen, err := buf.ReadU16()
	if err != nil {
		return err
	}
	r.DataLen = dataLen

	switch r.Type {
	case TypeA:
		raw, err := buf.ReadU32()
		if err != nil {
			return err
		}
		r.Addr = netip.AddrFrom4([4]byte{
			byte(raw >> 24),
			byte(raw >> 16),
			byte(raw >> 8),
			byte(raw),
		})
	case TypeAAAA:
		var addr [16]byte
		for i := 0; i < 16; i++ {
			b, err := buf.Read()
			if err != nil {
				return err
			}
			addr[i] = b
		}
		r.Addr = netip.AddrFrom16(addr)
	case TypeNS, TypeCNAME:
		host, err := buf.ReadQName()
		if err != nil {
			return err
		}
		r.Host = host
	case TypeMX:
		priority, err := buf.ReadU16()
		if err != nil {
			return err
		}
		r.Priority = priority
		host, err := buf.ReadQName()
		if err != nil {
			return err
		}
		r.Host = host
	default:
		// Type we don't know how to parse yet — skip the rdata so the cursor
		// stays aligned for whatever record follows.
		if err := buf.Step(int(dataLen)); err != nil {
			return err
		}
	}
	return nil
}

func (r Record) String() string {
	switch r.Type {
	case TypeA:
		return fmt.Sprintf("A %s -> %s (ttl=%d)", r.Domain, r.Addr, r.TTL)
	case TypeAAAA:
		return fmt.Sprintf("AAAA %s -> %s (ttl=%d)", r.Domain, r.Addr, r.TTL)
	case TypeNS:
		return fmt.Sprintf("NS %s -> %s (ttl=%d)", r.Domain, r.Host, r.TTL)
	case TypeCNAME:
		return fmt.Sprintf("CNAME %s -> %s (ttl=%d)", r.Domain, r.Host, r.TTL)
	case TypeMX:
		return fmt.Sprintf("MX %s -> %d %s (ttl=%d)", r.Domain, r.Priority, r.Host, r.TTL)
	default:
		return fmt.Sprintf("UNKNOWN(%d) %s (ttl=%d, len=%d)", uint16(r.Type), r.Domain, r.TTL, r.DataLen)
	}
}

func (r *Record) Write(buf *BytePacketBuffer) error {
	if err := r.writePreamble(buf); err != nil {
		return err
	}

	switch r.Type {
	case TypeA:
		if err := buf.WriteU16(4); err != nil {
			return err
		}
		for _, b := range r.Addr.As4() {
			if err := buf.WriteU8(b); err != nil {
				return err
			}
		}

	case TypeAAAA:
		if err := buf.WriteU16(16); err != nil {
			return err
		}
		for _, b := range r.Addr.As16() {
			if err := buf.WriteU8(b); err != nil {
				return err
			}
		}

	case TypeNS, TypeCNAME:
		lenPos := buf.Pos
		if err := buf.WriteU16(0); err != nil {
			return err
		}
		dataStart := buf.Pos
		if err := buf.WriteQName(r.Host); err != nil {
			return err
		}
		if err := buf.SetU16(lenPos, uint16(buf.Pos-dataStart)); err != nil {
			return err
		}

	case TypeMX:
		lenPos := buf.Pos
		if err := buf.WriteU16(0); err != nil {
			return err
		}
		dataStart := buf.Pos
		if err := buf.WriteU16(r.Priority); err != nil {
			return err
		}
		if err := buf.WriteQName(r.Host); err != nil {
			return err
		}
		if err := buf.SetU16(lenPos, uint16(buf.Pos-dataStart)); err != nil {
			return err
		}

	default:
		return fmt.Errorf("Write: unsupported record type %s", r.Type)
	}

	return nil
}

func (r *Record) writePreamble(buf *BytePacketBuffer) error {
	if err := buf.WriteQName(r.Domain); err != nil {
		return err
	}
	if err := buf.WriteU16(uint16(r.Type)); err != nil {
		return err
	}
	if err := buf.WriteU16(1); err != nil { // class IN
		return err
	}
	return buf.WriteU32(r.TTL)
}
