package dns

// Packet is a parsed DNS message: a 12-byte header followed by four sections
// of variable length. The Header's QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT fields
// tell us how many entries to expect in each section.
type Packet struct {
	Header      Header
	Questions   []Question
	Answers     []Record
	Authorities []Record
	Resources   []Record
}

func NewPacket() *Packet {
	return &Packet{}
}

// FromBuffer decodes a DNS message from buf, starting at the current cursor.
// On success, p is fully populated and the cursor sits just past the message.
func (p *Packet) FromBuffer(buf *BytePacketBuffer) error {
	if err := p.Header.Read(buf); err != nil {
		return err
	}

	p.Questions = make([]Question, 0, p.Header.Questions)
	for i := 0; i < int(p.Header.Questions); i++ {
		var q Question
		if err := q.Read(buf); err != nil {
			return err
		}
		p.Questions = append(p.Questions, q)
	}

	p.Answers = make([]Record, 0, p.Header.Answers)
	for i := 0; i < int(p.Header.Answers); i++ {
		var r Record
		if err := r.Read(buf); err != nil {
			return err
		}
		p.Answers = append(p.Answers, r)
	}

	p.Authorities = make([]Record, 0, p.Header.AuthoritativeEntries)
	for i := 0; i < int(p.Header.AuthoritativeEntries); i++ {
		var r Record
		if err := r.Read(buf); err != nil {
			return err
		}
		p.Authorities = append(p.Authorities, r)
	}

	p.Resources = make([]Record, 0, p.Header.ResourceEntries)
	for i := 0; i < int(p.Header.ResourceEntries); i++ {
		var r Record
		if err := r.Read(buf); err != nil {
			return err
		}
		p.Resources = append(p.Resources, r)
	}

	return nil
}

func (p *Packet) Write(buf *BytePacketBuffer) error {
	// Sync header section counts to slice lengths so a caller can just
	// append to slices without remembering to set Header.Questions etc.
	p.Header.Questions = uint16(len(p.Questions))
	p.Header.Answers = uint16(len(p.Answers))
	p.Header.AuthoritativeEntries = uint16(len(p.Authorities))
	p.Header.ResourceEntries = uint16(len(p.Resources))

	err := p.Header.Write(buf)
	if err != nil {
		return err
	}
	for _, question := range p.Questions {
		err = question.Write(buf)
		if err != nil {
			return err
		}
	}
	for _, answer := range p.Answers {
		err = answer.Write(buf)
		if err != nil {
			return err
		}
	}
	for _, authority := range p.Authorities {
		err = authority.Write(buf)
		if err != nil {
			return err
		}
	}
	for _, resource := range p.Resources {
		err = resource.Write(buf)
		if err != nil {
			return err
		}
	}
	return nil
}
