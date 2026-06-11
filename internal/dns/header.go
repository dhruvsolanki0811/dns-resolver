package dns

// ResultCode is the RCODE field of the DNS header — the 4-bit response status.
type ResultCode uint8

const (
	NoError  ResultCode = 0
	FormErr  ResultCode = 1
	ServFail ResultCode = 2
	NXDomain ResultCode = 3
	NotImp   ResultCode = 4
	Refused  ResultCode = 5
)

// Header is the 12-byte fixed-format header that opens every DNS message.
//
// Wire layout (each row = 2 bytes):
//
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                      ID                       |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |QR|  Opcode   |AA|TC|RD|RA| Z|AD|CD|  RCODE    |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                    QDCOUNT                    |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                    ANCOUNT                    |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                    NSCOUNT                    |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                    ARCOUNT                    |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type Header struct {
	ID uint16 // matches the request to its reply

	// First flags byte (bits 0-7 of the flags word):
	RecursionDesired    bool  // RD — client is asking the server to recurse
	TruncatedMessage    bool  // TC — message was truncated (oversized)
	AuthoritativeAnswer bool  // AA — server is authoritative for the zone
	Opcode              uint8 // 4 bits — query type (0=standard, 1=inverse, ...)
	Response            bool  // QR — false=query, true=response

	// Second flags byte (bits 8-15 of the flags word):
	Rescode            ResultCode // RCODE — 4 bits, 0=NoError
	CheckingDisabled   bool       // CD — DNSSEC
	AuthedData         bool       // AD — DNSSEC
	Z                  bool       // reserved, must be zero
	RecursionAvailable bool       // RA — server supports recursion

	Questions            uint16 // QDCOUNT — number of entries in question section
	Answers              uint16 // ANCOUNT — number of answer records
	AuthoritativeEntries uint16 // NSCOUNT — number of authority records
	ResourceEntries      uint16 // ARCOUNT — number of additional records
}

// Read decodes the next 12 bytes from buf into the header fields.
func (h *Header) Read(buf *BytePacketBuffer) error {
	id, err := buf.ReadU16()
	if err != nil {
		return err
	}
	h.ID = id

	flags, err := buf.ReadU16()
	if err != nil {
		return err
	}
	// flags is a 16-bit word; split into the two flag bytes.
	a := byte(flags >> 8)   // high byte: QR, Opcode, AA, TC, RD
	b := byte(flags & 0xFF) // low byte:  RA, Z, AD, CD, RCODE

	h.RecursionDesired    = a&(1<<0) != 0
	h.TruncatedMessage    = a&(1<<1) != 0
	h.AuthoritativeAnswer = a&(1<<2) != 0
	h.Opcode              = (a >> 3) & 0x0F
	h.Response            = a&(1<<7) != 0

	h.Rescode            = ResultCode(b & 0x0F)
	h.CheckingDisabled   = b&(1<<4) != 0
	h.AuthedData         = b&(1<<5) != 0
	h.Z                  = b&(1<<6) != 0
	h.RecursionAvailable = b&(1<<7) != 0

	h.Questions, err = buf.ReadU16()
	if err != nil {
		return err
	}
	h.Answers, err = buf.ReadU16()
	if err != nil {
		return err
	}
	h.AuthoritativeEntries, err = buf.ReadU16()
	if err != nil {
		return err
	}
	h.ResourceEntries, err = buf.ReadU16()
	if err != nil {
		return err
	}
	return nil
}

// Write encodes the header into 12 bytes at the current cursor position.
func (h *Header) Write(buf *BytePacketBuffer) error {
	if err := buf.WriteU16(h.ID); err != nil {
		return err
	}

	// Pack the booleans back into two flag bytes.
	var a, b byte
	if h.RecursionDesired {
		a |= 1 << 0
	}
	if h.TruncatedMessage {
		a |= 1 << 1
	}
	if h.AuthoritativeAnswer {
		a |= 1 << 2
	}
	a |= (h.Opcode & 0x0F) << 3
	if h.Response {
		a |= 1 << 7
	}

	b |= byte(h.Rescode) & 0x0F
	if h.CheckingDisabled {
		b |= 1 << 4
	}
	if h.AuthedData {
		b |= 1 << 5
	}
	if h.Z {
		b |= 1 << 6
	}
	if h.RecursionAvailable {
		b |= 1 << 7
	}

	if err := buf.WriteU8(a); err != nil {
		return err
	}
	if err := buf.WriteU8(b); err != nil {
		return err
	}

	if err := buf.WriteU16(h.Questions); err != nil {
		return err
	}
	if err := buf.WriteU16(h.Answers); err != nil {
		return err
	}
	if err := buf.WriteU16(h.AuthoritativeEntries); err != nil {
		return err
	}
	return buf.WriteU16(h.ResourceEntries)
}
