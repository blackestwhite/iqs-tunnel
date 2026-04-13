package protocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	PacketMagic   = "IQST"
	PacketVersion = 1
	PacketMACSize = 16

	TypeInfo uint8 = iota + 1
	TypeData
)

type Packet struct {
	Version   uint8
	Type      uint8
	SessionID uint64
	Payload   []byte
}

type InfoPayload struct {
	ClientIP   [4]byte
	ClientPort uint16
	SpoofIP    [4]byte
	SpoofPort  uint16
}

func (p Packet) Marshal(secret []byte) ([]byte, error) {
	if p.Version == 0 {
		p.Version = PacketVersion
	}
	if len(p.Payload) > 65535 {
		return nil, fmt.Errorf("payload too large: %d", len(p.Payload))
	}
	buf := bytes.NewBuffer(make([]byte, 0, 16+len(p.Payload)+PacketMACSize))
	buf.WriteString(PacketMagic)
	buf.WriteByte(p.Version)
	buf.WriteByte(p.Type)
	_ = binary.Write(buf, binary.BigEndian, p.SessionID)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(p.Payload)))
	buf.Write(p.Payload)
	buf.Write(computeMAC(buf.Bytes(), secret))
	return buf.Bytes(), nil
}

func UnmarshalPacket(raw, secret []byte) (Packet, error) {
	if len(raw) < 16+PacketMACSize {
		return Packet{}, fmt.Errorf("packet too short")
	}
	if string(raw[:4]) != PacketMagic {
		return Packet{}, fmt.Errorf("invalid packet magic")
	}
	if !hmac.Equal(raw[len(raw)-PacketMACSize:], computeMAC(raw[:len(raw)-PacketMACSize], secret)) {
		return Packet{}, fmt.Errorf("invalid packet mac")
	}
	body := raw[:len(raw)-PacketMACSize]
	if body[4] != PacketVersion {
		return Packet{}, fmt.Errorf("unsupported packet version %d", body[4])
	}
	payloadLen := binary.BigEndian.Uint16(body[14:16])
	if int(16+payloadLen) != len(body) {
		return Packet{}, fmt.Errorf("invalid packet payload length")
	}
	packet := Packet{
		Version:   body[4],
		Type:      body[5],
		SessionID: binary.BigEndian.Uint64(body[6:14]),
	}
	if payloadLen > 0 {
		packet.Payload = make([]byte, payloadLen)
		copy(packet.Payload, body[16:])
	}
	return packet, nil
}

func (i InfoPayload) MarshalBinary() []byte {
	buf := make([]byte, 12)
	copy(buf[0:4], i.ClientIP[:])
	binary.BigEndian.PutUint16(buf[4:6], i.ClientPort)
	copy(buf[6:10], i.SpoofIP[:])
	binary.BigEndian.PutUint16(buf[10:12], i.SpoofPort)
	return buf
}

func ParseInfoPayload(raw []byte) (InfoPayload, error) {
	if len(raw) != 12 {
		return InfoPayload{}, fmt.Errorf("invalid info payload length")
	}
	var info InfoPayload
	copy(info.ClientIP[:], raw[0:4])
	info.ClientPort = binary.BigEndian.Uint16(raw[4:6])
	copy(info.SpoofIP[:], raw[6:10])
	info.SpoofPort = binary.BigEndian.Uint16(raw[10:12])
	return info, nil
}

func computeMAC(raw, secret []byte) []byte {
	sum := hmac.New(sha256.New, secret)
	sum.Write(raw)
	return sum.Sum(nil)[:PacketMACSize]
}
