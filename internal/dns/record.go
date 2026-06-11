package dns

import (
	"fmt"
	"net/netip"
)

// Record is one resource record in the answer/authority/additional sections.
//
//	<name>            variable, length-prefixed labels (possibly compressed)
//	<type:u16>        DNS type code (A=1, NS=2, ...)
//	<class:u16>       always 1 (IN)
//	<ttl:u32>         seconds the answer can be cached
//	<rdlength:u16>    length in bytes of the rdata that follows
//	<rdata>           variable, parsed per type
type Record struct {
	Domain  string
	Type    QueryType
	TTL     uint32
	DataLen uint16

	Addr netip.Addr
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
	default:
		return fmt.Sprintf("UNKNOWN(%d) %s (ttl=%d, len=%d)", uint16(r.Type), r.Domain, r.TTL, r.DataLen)
	}
}
