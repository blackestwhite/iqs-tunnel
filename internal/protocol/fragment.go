package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	FragmentMagic   = "IQF"
	FragmentVersion = 1
)

type Fragment struct {
	Version       uint8
	SessionID     uint64
	PacketID      uint32
	PacketSize    uint32
	Nonce         uint32
	FragmentIndex uint8
	FragmentCount uint8
	Payload       []byte
}

func (f Fragment) MarshalBinary() ([]byte, error) {
	if f.Version == 0 {
		f.Version = FragmentVersion
	}
	if len(f.Payload) > 65535 {
		return nil, fmt.Errorf("fragment payload too large: %d", len(f.Payload))
	}
	buf := bytes.NewBuffer(make([]byte, 0, 28+len(f.Payload)))
	buf.WriteString(FragmentMagic)
	buf.WriteByte(f.Version)
	_ = binary.Write(buf, binary.BigEndian, f.SessionID)
	_ = binary.Write(buf, binary.BigEndian, f.PacketID)
	_ = binary.Write(buf, binary.BigEndian, f.PacketSize)
	_ = binary.Write(buf, binary.BigEndian, f.Nonce)
	buf.WriteByte(f.FragmentIndex)
	buf.WriteByte(f.FragmentCount)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(f.Payload)))
	buf.Write(f.Payload)
	return buf.Bytes(), nil
}

func UnmarshalFragment(raw []byte) (Fragment, error) {
	if len(raw) < 28 {
		return Fragment{}, fmt.Errorf("fragment too short")
	}
	if string(raw[:3]) != FragmentMagic {
		return Fragment{}, fmt.Errorf("invalid fragment magic")
	}
	if raw[3] != FragmentVersion {
		return Fragment{}, fmt.Errorf("unsupported fragment version %d", raw[3])
	}
	payloadLen := int(binary.BigEndian.Uint16(raw[26:28]))
	if len(raw) != 28+payloadLen {
		return Fragment{}, fmt.Errorf("fragment payload length mismatch")
	}
	f := Fragment{
		Version:       raw[3],
		SessionID:     binary.BigEndian.Uint64(raw[4:12]),
		PacketID:      binary.BigEndian.Uint32(raw[12:16]),
		PacketSize:    binary.BigEndian.Uint32(raw[16:20]),
		Nonce:         binary.BigEndian.Uint32(raw[20:24]),
		FragmentIndex: raw[24],
		FragmentCount: raw[25],
	}
	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		copy(f.Payload, raw[28:28+payloadLen])
	}
	return f, nil
}

func MaxDNSRawFragmentPayload(baseDomain string, maxQNameLen, maxLabelLen int) int {
	baseDomain = strings.Trim(baseDomain, ".")
	for payload := 1024; payload >= 32; payload-- {
		frag := Fragment{
			SessionID:     1,
			PacketID:      1,
			PacketSize:    uint32(payload),
			Nonce:         1,
			FragmentIndex: 0,
			FragmentCount: 1,
			Payload:       make([]byte, payload),
		}
		raw, _ := frag.MarshalBinary()
		name := EncodeDNSName(raw, baseDomain, maxLabelLen)
		if len(name) <= maxQNameLen {
			return payload
		}
	}
	return 0
}

func EncodeDNSName(raw []byte, baseDomain string, maxLabelLen int) string {
	encoded := EncodeBase32NoPad(raw)
	labels := make([]string, 0, (len(encoded)+maxLabelLen-1)/maxLabelLen+1)
	for len(encoded) > 0 {
		chunkLen := maxLabelLen
		if chunkLen > len(encoded) {
			chunkLen = len(encoded)
		}
		labels = append(labels, encoded[:chunkLen])
		encoded = encoded[chunkLen:]
	}
	baseDomain = strings.Trim(baseDomain, ".")
	if baseDomain != "" {
		labels = append(labels, strings.Split(baseDomain, ".")...)
	}
	return strings.Join(labels, ".")
}

func DecodeDNSName(qname, baseDomain string) ([]byte, error) {
	qname = strings.Trim(strings.ToLower(qname), ".")
	baseDomain = strings.Trim(strings.ToLower(baseDomain), ".")
	if baseDomain != "" {
		if qname == baseDomain {
			return nil, fmt.Errorf("missing fragment labels")
		}
		suffix := "." + baseDomain
		if !strings.HasSuffix(qname, suffix) {
			return nil, fmt.Errorf("qname %q does not match domain %q", qname, baseDomain)
		}
		qname = strings.TrimSuffix(qname, suffix)
	}
	return DecodeBase32NoPad(strings.ReplaceAll(qname, ".", ""))
}

func FragmentPacket(packetRaw []byte, sessionID uint64, packetID uint32, maxPayload int, nonce uint32) ([]Fragment, error) {
	if maxPayload <= 0 {
		return nil, fmt.Errorf("maxPayload must be positive")
	}
	fragmentCount := (len(packetRaw) + maxPayload - 1) / maxPayload
	if fragmentCount == 0 {
		fragmentCount = 1
	}
	fragments := make([]Fragment, 0, fragmentCount)
	for i := 0; i < fragmentCount; i++ {
		start := i * maxPayload
		end := start + maxPayload
		if end > len(packetRaw) {
			end = len(packetRaw)
		}
		payload := make([]byte, end-start)
		copy(payload, packetRaw[start:end])
		fragments = append(fragments, Fragment{
			SessionID:     sessionID,
			PacketID:      packetID,
			PacketSize:    uint32(len(packetRaw)),
			Nonce:         nonce,
			FragmentIndex: uint8(i),
			FragmentCount: uint8(fragmentCount),
			Payload:       payload,
		})
	}
	return fragments, nil
}

type packetKey struct {
	sessionID uint64
	packetID  uint32
}

type reassemblyEntry struct {
	packetSize    uint32
	fragmentCount uint8
	pieces        map[uint8][]byte
	lastTouch     time.Time
}

type Reassembler struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[packetKey]*reassemblyEntry
}

func NewReassembler(ttl time.Duration) *Reassembler {
	return &Reassembler{
		ttl:     ttl,
		entries: make(map[packetKey]*reassemblyEntry),
	}
}

func (r *Reassembler) Add(fragment Fragment) ([]byte, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.cleanupLocked(now)
	key := packetKey{sessionID: fragment.SessionID, packetID: fragment.PacketID}
	entry, ok := r.entries[key]
	if !ok {
		entry = &reassemblyEntry{
			packetSize:    fragment.PacketSize,
			fragmentCount: fragment.FragmentCount,
			pieces:        make(map[uint8][]byte, int(fragment.FragmentCount)),
			lastTouch:     now,
		}
		r.entries[key] = entry
	}
	if entry.packetSize != fragment.PacketSize || entry.fragmentCount != fragment.FragmentCount {
		return nil, false, fmt.Errorf("fragment metadata mismatch for packet %d", fragment.PacketID)
	}
	if _, exists := entry.pieces[fragment.FragmentIndex]; exists {
		return nil, false, nil
	}
	payloadCopy := make([]byte, len(fragment.Payload))
	copy(payloadCopy, fragment.Payload)
	entry.pieces[fragment.FragmentIndex] = payloadCopy
	entry.lastTouch = now

	packet, ok, err := entry.tryAssemble()
	if !ok || err != nil {
		return nil, false, err
	}
	delete(r.entries, key)
	return packet, true, nil
}

func (r *Reassembler) cleanupLocked(now time.Time) {
	if r.ttl <= 0 {
		return
	}
	for key, entry := range r.entries {
		if now.Sub(entry.lastTouch) > r.ttl {
			delete(r.entries, key)
		}
	}
}

func (e *reassemblyEntry) tryAssemble() ([]byte, bool, error) {
	if e.fragmentCount == 0 {
		return nil, false, fmt.Errorf("invalid fragment count")
	}
	if len(e.pieces) != int(e.fragmentCount) {
		return nil, false, nil
	}
	buf := make([]byte, 0, e.packetSize)
	for i := uint8(0); i < e.fragmentCount; i++ {
		piece, ok := e.pieces[i]
		if !ok {
			return nil, false, nil
		}
		buf = append(buf, piece...)
	}
	if uint32(len(buf)) < e.packetSize {
		return nil, false, fmt.Errorf("assembled packet too short")
	}
	return buf[:e.packetSize], true, nil
}
