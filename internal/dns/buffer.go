package dns

import (
	"errors"
	"strings"
)

// BytePacketBuffer holds one DNS packet plus a read/write cursor.
// DNS over UDP is capped at 512 bytes (before EDNS0), so the buffer is fixed.
type BytePacketBuffer struct {
	Buf [512]byte
	Pos int
}

func NewBytePacketBuffer() *BytePacketBuffer {
	return &BytePacketBuffer{}
}

func (b *BytePacketBuffer) Step(n int) error {
	b.Pos += n
	if b.Pos > len(b.Buf) {
		return errors.New("buffer step out of range")
	}
	return nil
}

// Seek sets the cursor to an absolute position.
func (b *BytePacketBuffer) Seek(n int) error {
	if n < 0 || n > len(b.Buf) {
		return errors.New("buffer seek out of range")
	}
	b.Pos = n
	return nil
}

// Read consumes one byte at the current cursor and advances.
func (b *BytePacketBuffer) Read() (byte, error) {
	if b.Pos >= len(b.Buf) {
		return 0, errors.New("buffer read past end")
	}
	v := b.Buf[b.Pos]
	b.Pos++
	return v, nil
}

// Get reads one byte at an absolute offset without moving the cursor.
func (b *BytePacketBuffer) Get(p int) (byte, error) {
	if p < 0 || p >= len(b.Buf) {
		return 0, errors.New("buffer get out of range")
	}
	return b.Buf[p], nil
}

// GetRange reads n bytes starting at p without moving the cursor.
func (b *BytePacketBuffer) GetRange(p, n int) ([]byte, error) {
	if p < 0 || p+n > len(b.Buf) {
		return nil, errors.New("buffer get_range out of range")
	}
	return b.Buf[p : p+n], nil
}

// ReadU16 reads a big-endian 16-bit value and advances 2 bytes.
func (b *BytePacketBuffer) ReadU16() (uint16, error) {
	hi, err := b.Read()
	if err != nil {
		return 0, err
	}
	lo, err := b.Read()
	if err != nil {
		return 0, err
	}
	return uint16(hi)<<8 | uint16(lo), nil
}

// ReadU32 reads a big-endian 32-bit value and advances 4 bytes.
func (b *BytePacketBuffer) ReadU32() (uint32, error) {
	var v uint32
	for i := 0; i < 4; i++ {
		x, err := b.Read()
		if err != nil {
			return 0, err
		}
		v = v<<8 | uint32(x)
	}
	return v, nil
}

func (b *BytePacketBuffer) ReadQName() (string, error) {
	const maxJumps = 5
	pos := b.Pos
	jumped := false
	jumps := 0

	var out strings.Builder
	delim := ""

	for {
		if jumps > maxJumps {
			return "", errors.New("qname pointer chain too long")
		}
		length, err := b.Get(pos)
		if err != nil {
			return "", err
		}

		// Top two bits = 11 → this is a pointer, not a label length.
		if length&0xC0 == 0xC0 {
			// First time we see a pointer, lock in the post-pointer cursor.
			if !jumped {
				if err := b.Seek(pos + 2); err != nil {
					return "", err
				}
			}
			b2, err := b.Get(pos + 1)
			if err != nil {
				return "", err
			}
			// Pointer offset = low 14 bits of the two pointer bytes.
			offset := (uint16(length)^0xC0)<<8 | uint16(b2)
			pos = int(offset)
			jumped = true
			jumps++
			continue
		}

		// Plain label: read its bytes, then continue with the next length byte.
		pos++
		if length == 0 {
			break
		}
		out.WriteString(delim)
		raw, err := b.GetRange(pos, int(length))
		if err != nil {
			return "", err
		}
		// DNS names are case-insensitive on the wire; normalize for matching.
		out.WriteString(strings.ToLower(string(raw)))
		delim = "."
		pos += int(length)
	}

	if !jumped {
		if err := b.Seek(pos); err != nil {
			return "", err
		}
	}
	return out.String(), nil
}

// -----------------------------------------------------------------------------
// Write side — used to build outgoing query packets and (later) responses.
// -----------------------------------------------------------------------------

// Write puts one byte at the cursor and advances.
func (b *BytePacketBuffer) Write(v byte) error {
	if b.Pos >= len(b.Buf) {
		return errors.New("buffer write past end")
	}
	b.Buf[b.Pos] = v
	b.Pos++
	return nil
}

func (b *BytePacketBuffer) WriteU8(v uint8) error {
	return b.Write(v)
}

// WriteU16 writes a big-endian 16-bit value (2 bytes).
func (b *BytePacketBuffer) WriteU16(v uint16) error {
	if err := b.Write(byte(v >> 8)); err != nil {
		return err
	}
	return b.Write(byte(v))
}

// WriteU32 writes a big-endian 32-bit value (4 bytes).
func (b *BytePacketBuffer) WriteU32(v uint32) error {
	if err := b.Write(byte(v >> 24)); err != nil {
		return err
	}
	if err := b.Write(byte(v >> 16)); err != nil {
		return err
	}
	if err := b.Write(byte(v >> 8)); err != nil {
		return err
	}
	return b.Write(byte(v))
}

// WriteQName encodes a name as length-prefixed labels terminated by a zero byte.
// Does NOT emit compression pointers — full labels are simpler and always correct.
// (Compression is a "nice to have" optimization, not a correctness requirement.)
func (b *BytePacketBuffer) WriteQName(name string) error {
	for _, label := range splitLabels(name) {
		if len(label) > 63 {
			return errors.New("label > 63 bytes")
		}
		if err := b.WriteU8(uint8(len(label))); err != nil {
			return err
		}
		for i := 0; i < len(label); i++ {
			if err := b.WriteU8(label[i]); err != nil {
				return err
			}
		}
	}
	return b.WriteU8(0)
}

// splitLabels splits "www.google.com" into ["www", "google", "com"].
// Empty labels (consecutive dots, trailing dot) are dropped.
func splitLabels(name string) []string {
	if name == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		out = append(out, name[start:])
	}
	return out
}

// SetU16 patches a 16-bit value at an absolute offset without moving the cursor.
// Used for back-filling an rdlength placeholder once we've written the rdata.
func (b *BytePacketBuffer) SetU16(pos int, v uint16) error {
	if pos < 0 || pos+1 >= len(b.Buf) {
		return errors.New("set_u16 out of range")
	}
	b.Buf[pos] = byte(v >> 8)
	b.Buf[pos+1] = byte(v)
	return nil
}
