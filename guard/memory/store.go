package memory

import "sync"

// Store is the interface for attack-signature storage backends. Implementations
// must be safe for concurrent use.
type Store interface {
	// Add persists a new signature. Implementations may evict old entries to
	// respect capacity limits.
	Add(sig *Signature) error

	// Search finds the most similar stored signature whose similarity to sig
	// meets or exceeds threshold. It returns the best match and true, or a nil
	// match and false when nothing qualifies.
	Search(sig *Signature, threshold float64) (*Match, bool)

	// Len returns the number of signatures currently stored.
	Len() int
}

// Match pairs a stored signature with the computed similarity score.
type Match struct {
	Signature  *Signature
	Similarity float64
}

// InMemoryStore is a thread-safe, bounded, in-memory Store that evicts the
// oldest signatures when maxSize is reached.
type InMemoryStore struct {
	mu         sync.RWMutex
	signatures []*Signature
	maxSize    int
}

// NewInMemoryStore creates an InMemoryStore that retains at most maxSize
// signatures.
func NewInMemoryStore(maxSize int) *InMemoryStore {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &InMemoryStore{
		signatures: make([]*Signature, 0, min(maxSize, 256)),
		maxSize:    maxSize,
	}
}

// Add appends a signature to the store. If the store has reached its maximum
// size the oldest signature is evicted first.
func (s *InMemoryStore) Add(sig *Signature) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict oldest when at capacity.
	if len(s.signatures) >= s.maxSize {
		// Shift slice forward by one, dropping the oldest entry.
		copy(s.signatures, s.signatures[1:])
		s.signatures[len(s.signatures)-1] = sig
	} else {
		s.signatures = append(s.signatures, sig)
	}
	return nil
}

// Search iterates over all stored signatures and returns the one with the
// highest similarity to sig, provided it meets or exceeds threshold. The search
// holds a read lock for its duration.
func (s *InMemoryStore) Search(sig *Signature, threshold float64) (*Match, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var best *Match
	for _, stored := range s.signatures {
		sim := sig.Similarity(stored)
		if sim < threshold {
			continue
		}
		if best == nil || sim > best.Similarity {
			best = &Match{
				Signature:  stored,
				Similarity: sim,
			}
		}
		// Perfect match; no need to continue.
		if sim == 1.0 {
			break
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

// Len returns the current number of stored signatures.
func (s *InMemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.signatures)
}
