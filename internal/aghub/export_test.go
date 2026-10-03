package aghub

import (
	"database/sql"
	"time"
)

// What the external tests (package aghub_test) may reach of the admission
// internals: the clock, the proof-of-work difficulty and seed, and the
// counters of the gate. Nothing here exists outside tests.

// SetClockForTest makes the store read f instead of time.Now for admission,
// probation, the trial credit and the inactive sweep.
func (s *Store) SetClockForTest(f func() time.Time) { s.clock = f }

// SetPowBitsForTest lowers the proof of work this process asks for, so a
// test can solve many quickly. Production never changes it (regpow.Bits).
func (s *Store) SetPowBitsForTest(bits int) {
	g := s.gate()
	g.mu.Lock()
	g.bits = bits
	g.mu.Unlock()
}

// PowSeedForTest is the challenge seed of the hour of now.
func (s *Store) PowSeedForTest(now time.Time) [32]byte {
	return s.gate().powSeed(uint64(now.UnixMilli()) / 3_600_000)
}

// PowBitsForTest is the proof of work this process asks for.
func (s *Store) PowBitsForTest() int {
	g := s.gate()
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.bits
}

// RegisterKELReplaysForTest is how many KELs /register has decoded and
// replayed in this process.
func RegisterKELReplaysForTest() int64 { return registerKELReplays.Load() }

// DBForTest is the store's database handle.
func (s *Store) DBForTest() *sql.DB { return s.db }

// GateCountsForTest is the gate's held places: today's open-registration
// places, the trial grants paid today, and the window places held by
// registrations in progress.
func (s *Store) GateCountsForTest() (signup, trials int, window int) {
	g := s.gate()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, n := range g.signup {
		signup += n
	}
	trials = g.trialN
	for _, n := range g.window {
		window += n
	}
	return signup, trials, window
}
