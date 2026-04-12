package protocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	AckReportMagic = "IQA"
	AckReportSize  = 40
)

type AckReport struct {
	SessionID uint64
	Ack       uint32
	AckBits   uint64
}

func (r AckReport) Marshal(secret []byte) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, AckReportSize))
	buf.WriteString(AckReportMagic)
	buf.WriteByte(PacketVersion)
	_ = binary.Write(buf, binary.BigEndian, r.SessionID)
	_ = binary.Write(buf, binary.BigEndian, r.Ack)
	_ = binary.Write(buf, binary.BigEndian, r.AckBits)
	mac := hmac.New(sha256.New, secret)
	mac.Write(buf.Bytes())
	buf.Write(mac.Sum(nil)[:16])
	return buf.Bytes()
}

func UnmarshalAckReport(raw, secret []byte) (AckReport, error) {
	if len(raw) != AckReportSize {
		return AckReport{}, fmt.Errorf("invalid ack report size")
	}
	if string(raw[:3]) != AckReportMagic {
		return AckReport{}, fmt.Errorf("invalid ack report magic")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(raw[:24])
	if !hmac.Equal(raw[24:], mac.Sum(nil)[:16]) {
		return AckReport{}, fmt.Errorf("invalid ack report mac")
	}
	return AckReport{
		SessionID: binary.BigEndian.Uint64(raw[4:12]),
		Ack:       binary.BigEndian.Uint32(raw[12:16]),
		AckBits:   binary.BigEndian.Uint64(raw[16:24]),
	}, nil
}
