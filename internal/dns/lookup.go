package dns

import (
	"errors"
	"net"
	"net/netip"
)

func Lookup(qname string, qtype QueryType, server netip.AddrPort) (*Packet, error) {
	pkt := &Packet{}
	pkt.Header.ID = 6666
	pkt.Header.RecursionDesired = true
	pkt.Questions = []Question{{Name: qname, Qtype: qtype}}

	req := NewBytePacketBuffer()
	if err := pkt.Write(req); err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(server))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(req.Buf[:req.Pos]); err != nil {
		return nil, err
	}

	resp := NewBytePacketBuffer()
	n, err := conn.Read(resp.Buf[:])
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("empty response from server")
	}

	out := &Packet{}
	if err := out.FromBuffer(resp); err != nil {
		return nil, err
	}
	return out, nil
}
