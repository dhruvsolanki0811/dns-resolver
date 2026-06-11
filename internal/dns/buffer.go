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
