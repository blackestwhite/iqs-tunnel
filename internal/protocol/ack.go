package protocol

import "sync"

type AckState struct {
	Ack  uint32
	Bits uint64
}

func (a AckState) Acks(seq uint32) bool {
	if seq <= a.Ack {
		return true
	}
	delta := seq - a.Ack
	if delta == 0 || delta > 64 {
		return false
	}
	return a.Bits&(uint64(1)<<(delta-1)) != 0
}

type ReceiverWindow struct {
	mu          sync.Mutex
	base        uint32
	seen        map[uint32]struct{}
	initialized bool
}

func NewReceiverWindow() *ReceiverWindow {
	return &ReceiverWindow{seen: make(map[uint32]struct{})}
}

func (w *ReceiverWindow) MarkReceived(seq uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.initialized {
		w.initialized = true
		w.base = seq
		return true
	}
	if seq == w.base {
		return false
	}
	if seq < w.base {
		return false
	}
	if _, exists := w.seen[seq]; exists {
		return false
	}
	w.seen[seq] = struct{}{}
	for {
		next := w.base + 1
		if _, ok := w.seen[next]; !ok {
			break
		}
		delete(w.seen, next)
		w.base = next
	}
	return true
}

func (w *ReceiverWindow) Snapshot() AckState {
	w.mu.Lock()
	defer w.mu.Unlock()

	var bits uint64
	for seq := range w.seen {
		if seq <= w.base {
			delete(w.seen, seq)
			continue
		}
		delta := seq - w.base
		if delta > 64 {
			continue
		}
		bits |= uint64(1) << (delta - 1)
	}
	return AckState{Ack: w.base, Bits: bits}
}
