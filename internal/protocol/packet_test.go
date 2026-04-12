package protocol

import "testing"

func TestPacketRoundTrip(t *testing.T) {
	secret := []byte("secret")
	raw, err := (Packet{
		Type:      TypeData,
		SessionID: 77,
		Seq:       9,
		Ack:       3,
		AckBits:   0b1011,
		Payload:   []byte("hello"),
	}).Marshal(secret)
	if err != nil {
		t.Fatalf("marshal packet: %v", err)
	}
	got, err := UnmarshalPacket(raw, secret)
	if err != nil {
		t.Fatalf("unmarshal packet: %v", err)
	}
	if got.SessionID != 77 || got.Seq != 9 || got.Ack != 3 || got.AckBits != 0b1011 || string(got.Payload) != "hello" {
		t.Fatalf("unexpected packet: %+v", got)
	}
}

func TestReassemblerWithParity(t *testing.T) {
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	fragments, err := FragmentPacket(payload, 1, 10, 400, 1, 123)
	if err != nil {
		t.Fatalf("fragment packet: %v", err)
	}
	if len(fragments) < 4 {
		t.Fatalf("expected parity fragment, got %d fragments", len(fragments))
	}
	reassembler := NewReassembler(0)
	for i, fragment := range fragments {
		if i == 1 {
			continue
		}
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
	t.Fatal("reassembler did not complete with one missing shard plus parity")
}

func TestReceiverWindowSnapshot(t *testing.T) {
	w := NewReceiverWindow()
	if !w.MarkReceived(5) {
		t.Fatal("expected first packet to be new")
	}
	w.MarkReceived(7)
	w.MarkReceived(6)
	state := w.Snapshot()
	if state.Ack != 7 || state.Bits != 0 {
		t.Fatalf("unexpected ack state: %+v", state)
	}
}
