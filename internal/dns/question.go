package dns

import "fmt"

type QueryType uint16

const (
	TypeUnknown QueryType = 0
	TypeA       QueryType = 1
)

// String renders the type as its registry name when known.
func (q QueryType) String() string {
	switch q {
	case TypeA:
		return "A"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint16(q))
	}
}

// Question is a single entry in the question section.
//
// Wire layout: <qname>  <qtype:u16>  <qclass:u16>
// qclass is always 1 (IN — internet) for our purposes; we read and discard.
type Question struct {
	Name  string
	Qtype QueryType
}

// Read pulls a question off the buffer starting at the current cursor.
func (q *Question) Read(buf *BytePacketBuffer) error {
	name, err := buf.ReadQName()
	if err != nil {
		return err
	}
	q.Name = name

	t, err := buf.ReadU16()
	if err != nil {
		return err
	}
	q.Qtype = QueryType(t)

	// qclass — always 1 (IN). We don't model non-IN classes, so just consume.
	if _, err := buf.ReadU16(); err != nil {
		return err
	}
	return nil
}

func (q *Question) Write(buf *BytePacketBuffer) error {
	err := buf.WriteQName(q.Name)
	if err != nil {
		return err
	}

	err = buf.WriteU16(uint16(q.Qtype))
	if err != nil {
		return err
	}

	return buf.WriteU16(uint16(1))
}
