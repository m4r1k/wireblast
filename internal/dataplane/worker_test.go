package dataplane

import (
	"testing"
	"time"
)

// fakeClock is a hand-advanced time source, so the stall state machine can be
// tested without sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestStall() (*txStall, *fakeClock) {
	// A clock that is not the zero time, so a live stall marker is always
	// distinguishable from a cleared one.
	c := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	return &txStall{now: c.now}, c
}

// The first empty batch must retry rather than sleep: the ring is almost always
// just full, and retrying is what drains it.
func TestTxStallFirstZeroSendRetries(t *testing.T) {
	s, _ := newTestStall()
	if s.backoff() {
		t.Fatal("first zero-send asked for a timer sleep, want a retry")
	}
	if s.since.IsZero() {
		t.Fatal("first zero-send did not start the stall clock")
	}
}

// Nothing reads the clock until a queue actually fails to transmit, which is
// what keeps the success path free of time.Now.
func TestTxStallDoesNotReadClockUntilStalled(t *testing.T) {
	s, _ := newTestStall()
	s.now = func() time.Time {
		t.Fatal("clock read outside a stall")
		return time.Time{}
	}
	s.clear()
	if !s.since.IsZero() {
		t.Fatal("clear left a stall marker behind")
	}
}

// Inside the budget the queue keeps retrying; at and past it, it sleeps.
func TestTxStallSleepsOnlyAfterBudget(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after time.Duration
		sleep bool
	}{
		{"well inside the budget", txStallAfter / 4, false},
		{"just inside the budget", txStallAfter - time.Nanosecond, false},
		{"exactly at the budget", txStallAfter, true},
		{"past the budget", 5 * txStallAfter, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, c := newTestStall()
			if s.backoff() {
				t.Fatal("first zero-send asked for a timer sleep, want a retry")
			}
			c.add(tc.after)
			if got := s.backoff(); got != tc.sleep {
				t.Fatalf("backoff() after %v = %v, want %v", tc.after, got, tc.sleep)
			}
		})
	}
}

// A queue that stays stuck keeps sleeping. The marker must not reset itself, or
// a downed link would spin a core for txStallAfter out of every cycle.
func TestTxStallStaysStalled(t *testing.T) {
	s, c := newTestStall()
	s.backoff()
	c.add(txStallAfter)
	start := s.since
	for i := range 100 {
		if !s.backoff() {
			t.Fatalf("call %d retried, want a timer sleep while still stalled", i)
		}
		c.add(txStallBackoff)
	}
	if !s.since.Equal(start) {
		t.Fatalf("stall start moved from %v to %v", start, s.since)
	}
}

// A successful batch clears the marker, so the next full ring gets its own
// retry budget rather than inheriting an expired one.
func TestTxStallClearedBySuccessGetsFreshBudget(t *testing.T) {
	s, c := newTestStall()
	s.backoff()
	c.add(10 * txStallAfter)
	if !s.backoff() {
		t.Fatal("want a timer sleep after a long stall")
	}

	s.clear() // a batch went out
	c.add(time.Second)

	if s.backoff() {
		t.Fatal("first zero-send after a successful batch asked for a timer sleep")
	}
	c.add(txStallAfter / 2)
	if s.backoff() {
		t.Fatal("second zero-send slept; the budget did not restart")
	}
}

// The reason clear is also called on the loop's own waits: a rate-limited run
// pauses for credit for up to rate.MaxWait, and a marker carried across that
// wait would send the next full ring straight to the timer.
func TestTxStallClearedByLoopWaitGetsFreshBudget(t *testing.T) {
	s, c := newTestStall()
	s.backoff()

	// Stand in for a limiter wait longer than the stall budget.
	c.add(2 * time.Millisecond)
	s.clear()

	if s.backoff() {
		t.Fatal("zero-send after a rate-credit wait asked for a timer sleep, want a retry")
	}
}
