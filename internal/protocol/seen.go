package protocol

import "sync"

type SeenWindow struct {
	mu          sync.Mutex
	base        uint32
	seen        map[uint32]struct{}
	initialized bool
}

func NewSeenWindow() *SeenWindow {
	return &SeenWindow{seen: make(map[uint32]struct{})}
}

func (w *SeenWindow) MarkSeen(id uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.initialized {
		w.initialized = true
		w.base = id
		return true
	}
	if id == w.base || id < w.base {
		return false
	}
	if _, exists := w.seen[id]; exists {
		return false
	}
	w.seen[id] = struct{}{}
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
