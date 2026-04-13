package protocol

import "testing"

func TestPacketRoundTrip(t *testing.T) {
	secret := []byte("secret")
	raw, err := (Packet{
		Type:      TypeData,
		SessionID: 77,
		Payload:   []byte("hello"),
	}).Marshal(secret)
	if err != nil {
		t.Fatalf("marshal packet: %v", err)
	}
	got, err := UnmarshalPacket(raw, secret)
	if err != nil {
		t.Fatalf("unmarshal packet: %v", err)
	}
	if got.SessionID != 77 || got.Type != TypeData || string(got.Payload) != "hello" {
		t.Fatalf("unexpected packet: %+v", got)
	}
}

func TestReassemblerRoundTrip(t *testing.T) {
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	fragments, err := FragmentPacket(payload, 1, 10, 400, 123)
	if err != nil {
		t.Fatalf("fragment packet: %v", err)
	}
	if len(fragments) < 4 {
		t.Fatalf("expected multiple fragments, got %d", len(fragments))
	}
	reassembler := NewReassembler(0)
	for _, fragment := range fragments {
		packet, done, err := reassembler.Add(fragment)
		if err != nil {
			t.Fatalf("add fragment: %v", err)
		}
		if done {
			if len(packet) != len(payload) {
				t.Fatalf("unexpected reassembled length: %d", len(packet))
			}
			for i := range packet {
				if packet[i] != payload[i] {
					t.Fatalf("payload mismatch at %d", i)
				}
			}
			return
		}
	}
	t.Fatal("reassembler did not complete")
}

func TestSeenWindow(t *testing.T) {
	w := NewSeenWindow()
	if !w.MarkSeen(5) {
		t.Fatal("expected first packet to be new")
	}
	if w.MarkSeen(5) {
		t.Fatal("expected duplicate packet to be rejected")
	}
	if !w.MarkSeen(7) {
		t.Fatal("expected new out-of-order packet to be accepted")
	}
	if !w.MarkSeen(6) {
		t.Fatal("expected missing packet to be accepted")
	}
	if w.MarkSeen(6) {
		t.Fatal("expected duplicate after merge to be rejected")
	}
}
