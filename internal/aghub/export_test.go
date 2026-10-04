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

// MoveBalanceWithoutEntryForTest reproduces the shape the settlement path
// left before it wrote ledger entries: a balance that moved with nothing
// behind it.
func (s *Store) MoveBalanceWithoutEntryForTest(aid string, delta int64) error {
	_, err := s.db.Exec(
		`INSERT INTO credit_balance(aid, credits) VALUES(?,?)
		 ON CONFLICT(aid) DO UPDATE SET credits = credits + ?`, aid, delta, delta)
	return err
}

// SetDirBucketRateForTest replaces the per-address bucket of
// /directory:bucket (DirBucketPerMinute, DirBucketBurst), for a test that
// queries more often than an address may.
func (s *Server) SetDirBucketRateForTest(perMinute float64, burst int) {
	s.dirLimiter = newRateLimiter(perMinute/60, burst)
}

// SetDirLimiterClockForTest makes the /directory:bucket limiter read f.
func (s *Server) SetDirLimiterClockForTest(f func() time.Time) {
	s.dirLimiter.mu.Lock()
	s.dirLimiter.now = f
	s.dirLimiter.mu.Unlock()
}

// ForgetDirMaxBitsForTest makes the next DirMaxBits compute dir_max_bits
// again, as it does when it is DirMaxBitsEvery old.
func (s *Store) ForgetDirMaxBitsForTest() {
	s.dirBits.mu.Lock()
	s.dirBits.valid = false
	s.dirBits.mu.Unlock()
}

// SetDirNoticeForTest makes the directory entries carry the notice f gives
// (as the notices this hub keeps as a witness will).
func (s *Store) SetDirNoticeForTest(f func(aid string) []byte) {
	s.dirNotice = func(_ rowQuerier, aid string) ([]byte, error) { return f(aid), nil }
}

// DirMaxBitsOfForTest is dirMaxBits over the given 64-bit hash prefixes.
func DirMaxBitsOfForTest(prefixes []uint64) int { return dirMaxBits(prefixes) }

// PublishDueAtForTest is PublishDue with the clock reading at, so a test can
// close an epoch without moving the clock every other part of the hub reads.
func (s *Store) PublishDueAtForTest(at time.Time) (*SupplyEpochEntry, error) {
	return s.publishDueAt(at)
}

// LiabilityProofAtForTest is LiabilityProof with the clock reading at.
func (s *Store) LiabilityProofAtForTest(aid string, toDay *uint64, at time.Time) (LiabilityProof, error) {
	return s.liabilityProofAt(aid, toDay, at)
}

// PruneLiabilityProofsAtForTest is PruneLiabilityProofs with the clock
// reading at.
func (s *Store) PruneLiabilityProofsAtForTest(at time.Time) error {
	return s.pruneLiabilityProofsAt(at)
}

// DepthForTest is the tree depth an epoch states.
func (e SupplyEpochEntry) DepthForTest() int { return e.depth }
