package dnsmsg

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	TypeTXT = 16
	ClassIN = 1
)

type Question struct {
	ID           uint16
	Flags        uint16
	Name         string
	Type         uint16
	Class        uint16
	QuestionWire []byte
}

func BuildTXTQuery(id uint16, qname string) ([]byte, error) {
	nameWire, err := encodeName(qname)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 12+len(nameWire)+4)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	copy(msg[12:], nameWire)
	binary.BigEndian.PutUint16(msg[12+len(nameWire):14+len(nameWire)], TypeTXT)
	binary.BigEndian.PutUint16(msg[14+len(nameWire):16+len(nameWire)], ClassIN)
	return msg, nil
}

func ParseQuestion(msg []byte) (Question, error) {
	if len(msg) < 17 {
		return Question{}, fmt.Errorf("dns message too short")
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	if qdcount != 1 {
		return Question{}, fmt.Errorf("expected exactly one question")
	}
	name, next, err := decodeName(msg, 12)
	if err != nil {
		return Question{}, err
	}
	if next+4 > len(msg) {
		return Question{}, fmt.Errorf("dns question truncated")
	}
	q := Question{
		ID:           binary.BigEndian.Uint16(msg[0:2]),
		Flags:        binary.BigEndian.Uint16(msg[2:4]),
		Name:         name,
		Type:         binary.BigEndian.Uint16(msg[next : next+2]),
		Class:        binary.BigEndian.Uint16(msg[next+2 : next+4]),
		QuestionWire: append([]byte(nil), msg[12:next+4]...),
	}
	return q, nil
}

func BuildTXTResponse(q Question, txt string) ([]byte, error) {
	rdata := packTXT(txt)
	answerLen := len(q.QuestionWire[:len(q.QuestionWire)-4]) + 10 + len(rdata)
	msg := make([]byte, 12+len(q.QuestionWire)+answerLen)
	binary.BigEndian.PutUint16(msg[0:2], q.ID)
	binary.BigEndian.PutUint16(msg[2:4], 0x8400|(q.Flags&0x0110))
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	copy(msg[12:], q.QuestionWire)

	offset := 12 + len(q.QuestionWire)
	copy(msg[offset:], q.QuestionWire[:len(q.QuestionWire)-4])
	offset += len(q.QuestionWire) - 4
	binary.BigEndian.PutUint16(msg[offset:offset+2], TypeTXT)
	binary.BigEndian.PutUint16(msg[offset+2:offset+4], ClassIN)
	binary.BigEndian.PutUint32(msg[offset+4:offset+8], 0)
	binary.BigEndian.PutUint16(msg[offset+8:offset+10], uint16(len(rdata)))
	copy(msg[offset+10:], rdata)
	return msg, nil
}

func ParseTXTResponse(msg []byte) (uint16, []string, error) {
	if len(msg) < 12 {
		return 0, nil, fmt.Errorf("dns response too short")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])
	offset := 12
	for i := 0; i < int(qdcount); i++ {
		_, next, err := decodeName(msg, offset)
		if err != nil {
			return 0, nil, err
		}
		offset = next + 4
		if offset > len(msg) {
			return 0, nil, fmt.Errorf("dns response truncated in question")
		}
	}
	txts := make([]string, 0, ancount)
	for i := 0; i < int(ancount); i++ {
		_, next, err := decodeName(msg, offset)
		if err != nil {
			return 0, nil, err
		}
		if next+10 > len(msg) {
			return 0, nil, fmt.Errorf("dns answer header truncated")
		}
		rtype := binary.BigEndian.Uint16(msg[next : next+2])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdataStart := next + 10
		rdataEnd := rdataStart + rdLen
		if rdataEnd > len(msg) {
			return 0, nil, fmt.Errorf("dns answer rdata truncated")
		}
		if rtype == TypeTXT {
			txt, err := unpackTXT(msg[rdataStart:rdataEnd])
			if err != nil {
				return 0, nil, err
			}
			txts = append(txts, txt)
		}
		offset = rdataEnd
	}
	return id, txts, nil
}

func encodeName(name string) ([]byte, error) {
	name = strings.Trim(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	labels := strings.Split(name, ".")
	size := 1
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label %q", label)
		}
		size += 1 + len(label)
	}
	out := make([]byte, 0, size)
	for _, label := range labels {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out, nil
}

func decodeName(msg []byte, offset int) (string, int, error) {
	labels := make([]string, 0, 4)
	for {
		if offset >= len(msg) {
			return "", 0, fmt.Errorf("dns name truncated")
		}
		n := int(msg[offset])
		offset++
		if n == 0 {
			return strings.Join(labels, "."), offset, nil
		}
		if n&0xC0 != 0 {
			return "", 0, fmt.Errorf("compressed names are not supported here")
		}
		if offset+n > len(msg) {
			return "", 0, fmt.Errorf("dns label truncated")
		}
		labels = append(labels, strings.ToLower(string(msg[offset:offset+n])))
		offset += n
	}
}

func packTXT(text string) []byte {
	data := []byte(text)
	if len(data) <= 255 {
		return append([]byte{byte(len(data))}, data...)
	}
	buf := make([]byte, 0, len(data)+len(data)/255+1)
	for len(data) > 0 {
		n := 255
		if n > len(data) {
			n = len(data)
		}
		buf = append(buf, byte(n))
		buf = append(buf, data[:n]...)
		data = data[n:]
	}
	return buf
}

func unpackTXT(raw []byte) (string, error) {
	var out []byte
	for len(raw) > 0 {
		n := int(raw[0])
		raw = raw[1:]
		if n > len(raw) {
			return "", fmt.Errorf("txt length exceeds rdata")
		}
		out = append(out, raw[:n]...)
		raw = raw[n:]
	}
	return string(out), nil
}
