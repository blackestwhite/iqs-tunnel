package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"sync"
	"time"
)

const (
	FragmentMagic   = "IQF"
	FragmentVersion = 1
	FlagParity      = 1 << 0
)

type Fragment struct {
	Version       uint8
	SessionID     uint64
	PacketSeq     uint32
	PacketSize    uint32
	Nonce         uint32
	FragmentIndex uint8
	DataShards    uint8
	ParityShards  uint8
	Flags         uint8
	Payload       []byte
}

func (f Fragment) MarshalBinary() ([]byte, error) {
	if f.Version == 0 {
		f.Version = FragmentVersion
	}
	if len(f.Payload) > 65535 {
		return nil, fmt.Errorf("fragment payload too large: %d", len(f.Payload))
	}
	buf := bytes.NewBuffer(make([]byte, 0, 30+len(f.Payload)+4))
	buf.WriteString(FragmentMagic)
	buf.WriteByte(f.Version)
	_ = binary.Write(buf, binary.BigEndian, f.SessionID)
	_ = binary.Write(buf, binary.BigEndian, f.PacketSeq)
	_ = binary.Write(buf, binary.BigEndian, f.PacketSize)
	_ = binary.Write(buf, binary.BigEndian, f.Nonce)
	buf.WriteByte(f.FragmentIndex)
	buf.WriteByte(f.DataShards)
	buf.WriteByte(f.ParityShards)
	buf.WriteByte(f.Flags)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(f.Payload)))
	buf.Write(f.Payload)
	crc := crc32.ChecksumIEEE(buf.Bytes())
	_ = binary.Write(buf, binary.BigEndian, crc)
	return buf.Bytes(), nil
}

func UnmarshalFragment(raw []byte) (Fragment, error) {
	if len(raw) < 30 {
		return Fragment{}, fmt.Errorf("fragment too short")
	}
	if string(raw[:3]) != FragmentMagic {
		return Fragment{}, fmt.Errorf("invalid fragment magic")
	}
	if raw[3] != FragmentVersion {
		return Fragment{}, fmt.Errorf("unsupported fragment version %d", raw[3])
	}
	wantCRC := binary.BigEndian.Uint32(raw[len(raw)-4:])
	if got := crc32.ChecksumIEEE(raw[:len(raw)-4]); got != wantCRC {
		return Fragment{}, fmt.Errorf("fragment crc mismatch")
	}
	payloadLen := int(binary.BigEndian.Uint16(raw[28:30]))
	if len(raw) != 30+payloadLen+4 {
		return Fragment{}, fmt.Errorf("fragment payload length mismatch")
	}
	f := Fragment{
		Version:       raw[3],
		SessionID:     binary.BigEndian.Uint64(raw[4:12]),
		PacketSeq:     binary.BigEndian.Uint32(raw[12:16]),
		PacketSize:    binary.BigEndian.Uint32(raw[16:20]),
		Nonce:         binary.BigEndian.Uint32(raw[20:24]),
		FragmentIndex: raw[24],
		DataShards:    raw[25],
		ParityShards:  raw[26],
		Flags:         raw[27],
	}
	payloadLen = int(binary.BigEndian.Uint16(raw[28:30]))
	if len(raw) != 30+payloadLen+4 {
		return Fragment{}, fmt.Errorf("fragment payload length mismatch")
	}
	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		copy(f.Payload, raw[30:30+payloadLen])
	}
	return f, nil
}

func MaxDNSRawFragmentPayload(baseDomain string, maxQNameLen, maxLabelLen int) int {
	baseDomain = strings.Trim(baseDomain, ".")
	for payload := 1024; payload >= 32; payload-- {
		frag := Fragment{
			SessionID:     1,
			PacketSeq:     1,
			PacketSize:    uint32(payload),
			Nonce:         1,
			FragmentIndex: 0,
			DataShards:    1,
			ParityShards:  0,
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

func FragmentPacket(packetRaw []byte, sessionID uint64, packetSeq uint32, maxPayload int, parityShards int, nonce uint32) ([]Fragment, error) {
	if maxPayload <= 0 {
		return nil, fmt.Errorf("maxPayload must be positive")
	}
	if parityShards < 0 || parityShards > 1 {
		return nil, fmt.Errorf("only 0 or 1 parity shard is supported")
	}
	dataShards := (len(packetRaw) + maxPayload - 1) / maxPayload
	if dataShards == 0 {
		dataShards = 1
	}
	fragments := make([]Fragment, 0, dataShards+parityShards)
	maxShardLen := 0
	for i := 0; i < dataShards; i++ {
		start := i * maxPayload
		end := start + maxPayload
		if end > len(packetRaw) {
			end = len(packetRaw)
		}
		payload := make([]byte, end-start)
		copy(payload, packetRaw[start:end])
		if len(payload) > maxShardLen {
			maxShardLen = len(payload)
		}
		fragments = append(fragments, Fragment{
			SessionID:     sessionID,
			PacketSeq:     packetSeq,
			PacketSize:    uint32(len(packetRaw)),
			Nonce:         nonce,
			FragmentIndex: uint8(i),
			DataShards:    uint8(dataShards),
			ParityShards:  uint8(parityShards),
			Payload:       payload,
		})
	}
	if parityShards == 1 && dataShards > 1 {
		parity := make([]byte, maxShardLen)
		for _, fragment := range fragments {
			for i := range parity {
				if i < len(fragment.Payload) {
					parity[i] ^= fragment.Payload[i]
				}
			}
		}
		fragments = append(fragments, Fragment{
			SessionID:     sessionID,
			PacketSeq:     packetSeq,
			PacketSize:    uint32(len(packetRaw)),
			Nonce:         nonce,
			FragmentIndex: uint8(dataShards),
			DataShards:    uint8(dataShards),
			ParityShards:  1,
			Flags:         FlagParity,
			Payload:       parity,
		})
	}
	return fragments, nil
}

type packetKey struct {
	sessionID uint64
	packetSeq uint32
}

type reassemblyEntry struct {
	packetSize   uint32
	dataShards   uint8
	parityShards uint8
	pieces       map[uint8][]byte
	createdAt    time.Time
	lastTouch    time.Time
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
	key := packetKey{sessionID: fragment.SessionID, packetSeq: fragment.PacketSeq}
	entry, ok := r.entries[key]
	if !ok {
		entry = &reassemblyEntry{
			packetSize:   fragment.PacketSize,
			dataShards:   fragment.DataShards,
			parityShards: fragment.ParityShards,
			pieces:       make(map[uint8][]byte, int(fragment.DataShards)+int(fragment.ParityShards)),
			createdAt:    now,
			lastTouch:    now,
		}
		r.entries[key] = entry
	}
	if entry.packetSize != fragment.PacketSize || entry.dataShards != fragment.DataShards || entry.parityShards != fragment.ParityShards {
		return nil, false, fmt.Errorf("fragment metadata mismatch for packet %d", fragment.PacketSeq)
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
	if e.dataShards == 0 {
		return nil, false, fmt.Errorf("invalid shard count")
	}
	missing := -1
	for i := uint8(0); i < e.dataShards; i++ {
		if _, ok := e.pieces[i]; !ok {
			if missing >= 0 {
				return nil, false, nil
			}
			missing = int(i)
		}
	}
	if missing >= 0 {
		if e.parityShards != 1 {
			return nil, false, nil
		}
		parityIndex := e.dataShards
		parity, ok := e.pieces[parityIndex]
		if !ok {
			return nil, false, nil
		}
		recovered := make([]byte, len(parity))
		copy(recovered, parity)
		for i := uint8(0); i < e.dataShards; i++ {
			if int(i) == missing {
				continue
			}
			payload := e.pieces[i]
			for j := range recovered {
				if j < len(payload) {
					recovered[j] ^= payload[j]
				}
			}
		}
		e.pieces[uint8(missing)] = trimRecovered(recovered, int(e.packetSize), int(e.dataShards), missing)
	}

	buf := make([]byte, 0, e.packetSize)
	for i := uint8(0); i < e.dataShards; i++ {
		buf = append(buf, e.pieces[i]...)
	}
	if uint32(len(buf)) < e.packetSize {
		return nil, false, fmt.Errorf("assembled packet too short")
	}
	return buf[:e.packetSize], true, nil
}

func trimRecovered(recovered []byte, packetSize int, dataShards int, shardIndex int) []byte {
	if dataShards <= 1 {
		out := make([]byte, packetSize)
		copy(out, recovered[:packetSize])
		return out
	}

	expected := len(recovered)
	if shardIndex == dataShards-1 {
		fullShards := dataShards - 1
		remaining := packetSize - (fullShards * len(recovered))
		if remaining > 0 && remaining < expected {
			expected = remaining
		}
	}
	if expected > len(recovered) {
		expected = len(recovered)
	}
	out := make([]byte, expected)
	copy(out, recovered[:expected])
	return out
}
