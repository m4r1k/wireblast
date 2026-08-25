package dataplane

import (
	"context"
	"errors"
	"runtime"
	"time"

	afxdp "github.com/atoonk/go-afxdp"

	"github.com/atoonk/wireblast/internal/generator"
	"github.com/atoonk/wireblast/internal/stats"
)

// fcsLen is the frame check sequence the NIC appends. Wireblast never writes
// it, but counts it, so reported frame sizes match --packet-size.
const fcsLen = 4

// wireOverhead is the on-the-wire framing beyond the frame itself: 7-byte
// preamble + 1-byte start-frame delimiter + 12-byte interframe gap.
const wireOverhead = 20

// errNothingBuilt is the jumbo sender's stand-in for the error SendFunc raises
// when its build callback fails: the generator had nothing to give, so the
// batch is empty. It is only ever seen alongside a non-zero build-error count.
var errNothingBuilt = errors.New("generator produced no packets")

// pacingFloor is the smallest wait a PCAP replay in original-timing mode will
// actually sleep. Timer granularity on Linux is tens of microseconds, so
// shorter gaps are accumulated and paid off together.
const pacingFloor = 250 * time.Microsecond

// txStallAfter is how long a queue may go without queueing a packet before a
// full transmit ring is read as a sustained stall rather than the kernel simply
// being busy draining it.
const txStallAfter = time.Millisecond

// txStallBackoff bounds CPU use once a queue is genuinely stalled, a downed
// link being the usual reason. Transient ring pressure retries instead, so the
// hot path never pays timer overshoot.
const txStallBackoff = 250 * time.Microsecond

// txAccum totals one batch as it is built. The frame check sequence the NIC
// will append is included, so byte totals and average frame sizes come out in
// the same units as --packet-size.
type txAccum struct {
	bytes     uint64
	clsPkts   [3]int
	clsBytes  [3]uint64
	buildErrs int
}

// add folds one built packet in.
func (a *txAccum) add(n int, class stats.Class) {
	a.bytes += uint64(n + fcsLen)
	a.clsPkts[class]++
	a.clsBytes[class] += uint64(n + fcsLen)
}

// txLoop is one queue's transmit loop. It owns this socket's transmit side
// exclusively, which is what makes the lock-free go-afxdp contract hold.
//
// Nothing in the steady state allocates: the generator writes straight into
// the UMEM frame, the rate limiter hands out batch credit, and the counters
// are atomics updated once per batch.
func (r *Runner) txLoop(ctx context.Context, queue int, xsk *afxdp.Socket, gen generator.Generator) {
	ctr := r.collector.Queue(queue)
	el := newErrLog(r.logf)
	sleeper := newSleeper()
	defer sleeper.stop()
	stall := newTxStall()

	pacer, paced := gen.(generator.Pacer)
	finite, isFinite := gen.(generator.Finite)
	avgWire := gen.AvgWireBytes()

	// Place this goroutine beside its queue's interrupt, and remember whether
	// it worked: owning a core decides how this loop may wait on a full ring,
	// in the branch below. Pinning here rather than letting the first send do
	// it means the answer is known before the loop needs it.
	cpu, err := xsk.Pin()
	if err != nil {
		el.printf("queue %d: %v", queue, err)
	}
	pinned := cpu >= 0

	// One accumulator per queue, reset per batch. It is a single heap object
	// the send callback writes through, rather than several separately
	// captured variables: the callback is handed to go-afxdp and so escapes,
	// which would escape each variable on its own.
	acc := &txAccum{}

	// owed is unslept capture time accumulated in original-timing mode.
	var owed time.Duration

	// send builds and queues up to want packets, returning how many the kernel
	// took. Which implementation runs is decided once, here, rather than per
	// batch.
	batchCap, send := r.sender(xsk, gen, acc)

	for {
		if ctx.Err() != nil {
			return
		}

		want := batchCap
		if isFinite {
			switch left := finite.Remaining(); {
			case left == 0:
				return // a one-pass replay has sent everything it has
			case left > 0 && left < want:
				want = left
			}
		}
		if paced {
			// The capture's own timing governs: one packet at a time, waiting
			// out the recorded gap. The rate limiter still applies on top, so
			// whichever is slower wins.
			//
			// Gaps are accumulated rather than slept individually. A capture
			// taken at 60 kpps has ~16 µs between packets, but no timer on
			// Linux is accurate anywhere near that, so sleeping each gap
			// separately would stretch the replay several times over. Waiting
			// only once the debt is worth sleeping on keeps the total elapsed
			// time honest, at the cost of micro-jitter nobody can observe.
			want = 1
			owed += pacer.Delay()
			if owed >= pacingFloor {
				// Waiting out a capture's own gap is the loop pausing on
				// purpose, not a queue that cannot transmit.
				stall.clear()
				if !sleeper.sleep(ctx, owed) {
					return
				}
				owed = 0
			}
		}

		grant, wait := r.limiter.Acquire(want, avgWire)
		if grant.Packets == 0 {
			// Same as the pacing wait above: no rate credit yet is a wait this
			// loop chose. Carrying a stall marker across it would send the next
			// full ring straight to the timer instead of retrying.
			stall.clear()
			if !sleeper.sleep(ctx, wait) {
				return
			}
			continue
		}

		*acc = txAccum{}

		sent, err := send(grant.Packets)

		switch {
		case err != nil && closedSocket(err):
			return // the socket was closed under us during shutdown
		case err != nil:
			// Nothing was queued, so none of the accumulated counts happened.
			//
			// The stall clock is deliberately left alone here. Every form of
			// ring backpressure comes back as a zero count and no error, so an
			// error means malformed input rather than a busy queue, and says
			// nothing about whether the ring drained. Clearing it on a
			// condition that can repeat forever is the one way this loop could
			// spin unbounded; keeping it costs at most one extra short sleep in
			// a run that is already failing.
			ctr.TxErrors.Add(1)
			r.limiter.Settle(grant, 0, 0)
			if acc.buildErrs == 0 {
				el.printf("queue %d: transmit: %v", queue, err)
			}
			if acc.buildErrs > 0 {
				return // the generator is exhausted mid-batch; this queue is done
			}
			continue
		}

		for c := range acc.clsPkts {
			if acc.clsPkts[c] > 0 {
				ctr.AddTx(acc.clsPkts[c], acc.clsBytes[c], stats.Class(c))
			}
		}
		r.limiter.Settle(grant, sent, acc.bytes+uint64(sent)*wireOverhead)

		if sent == 0 {
			// A full ring is normally transient, and retrying is what clears
			// it: SendFunc reclaims completed frames and kicks the driver on
			// the way in, so sleeping here suspends the only thing that unsticks
			// the queue. Timer overshoot on Linux runs to hundreds of
			// microseconds, far longer than a ring this deep stays busy, so a
			// sleep drains the NIC dry. Come straight back instead.
			//
			// How to wait depends on whether this worker owns its core.
			//
			// Pinned, go straight back round. runtime.Gosched() on a goroutine
			// locked to its thread is not the cheap run-queue shuffle it is for
			// a floating one: the scheduler puts the goroutine on the global
			// run queue under a process-wide lock, wakes a spinning thread to
			// hunt for work, hands this thread's processor away, parks the
			// thread, and wakes it again once another thread picks the
			// goroutine back up. That is a cross-core rendezvous per yield, and
			// at line rate a full ring is the normal condition rather than a
			// rare one, so it lands on other cores as scheduler overhead: 16
			// queues cost 23 cores where they should cost 16. Nothing else
			// wants this processor, so nothing is owed a turn.
			//
			// Unpinned, yield as before. Then the worker is sharing processors
			// with every other goroutine in the process, and there may be more
			// workers than there are processors to run them — a container CPU
			// quota, generic-mode XDP, an unrecognised driver, WithoutAffinity,
			// or simply no room left to place this queue. Spinning without
			// yielding there starves the stats, signal and duration goroutines
			// until the runtime preempts by signal some milliseconds later, and
			// with a single processor it does not make progress at all.
			//
			// A queue that makes no progress at all is a different thing again:
			// a downed link would otherwise spin a core forever. Once one has
			// been stuck for txStallAfter, fall back to a cancellable timer.
			if !stall.backoff() {
				if !pinned {
					runtime.Gosched()
				}
				continue
			}
			if !sleeper.sleep(ctx, txStallBackoff) {
				return
			}
			continue
		}
		stall.clear()
	}
}

// sender picks how this run puts packets on the wire and returns the batch
// size that goes with it. Every packet the kernel accepts is folded into acc;
// acc.buildErrs is incremented when the generator has nothing left to give.
//
// The two differ in where the packet is written. Normally the generator
// serialises straight into the UMEM frame and nothing is copied. That is not
// expressible for a packet larger than a frame: SendFunc hands out exactly one
// frame and never sets XDP_PKT_CONTD, so it cannot chain. The jumbo path
// stages the packet in ordinary memory and lets SendBatch split it across
// frames, paying one copy per packet. That is affordable precisely because a
// packet needing chaining is at least a frame long, so the packet rate is low.
func (r *Runner) sender(
	xsk *afxdp.Socket,
	gen generator.Generator,
	acc *txAccum,
) (int, func(want int) (int, error)) {
	if !r.multiBuffer {
		// Built once rather than per batch: it captures only gen and acc, both
		// fixed for the life of the queue.
		build := func(_ int, frame []byte) int {
			n, class := gen.Next(frame)
			if n <= 0 {
				// A generator with nothing left. Returning 0 would put an
				// empty frame on the wire, so report it as a build failure:
				// SendFunc abandons the whole batch unqueued.
				acc.buildErrs++
				return -1
			}
			acc.add(n, class)
			return n
		}
		return txBatch, func(want int) (int, error) {
			return xsk.SendFunc(want, build)
		}
	}

	// Allocated once per queue, so the steady state still allocates nothing.
	var (
		arena    = make([]byte, jumboTxBatch*r.maxFrame)
		payloads = make([][]byte, jumboTxBatch)
		pktLen   [jumboTxBatch]int
		pktClass [jumboTxBatch]stats.Class
	)
	return jumboTxBatch, func(want int) (int, error) {
		if want > jumboTxBatch {
			want = jumboTxBatch
		}
		built := 0
		for i := range want {
			buf := arena[i*r.maxFrame : (i+1)*r.maxFrame]
			n, class := gen.Next(buf)
			if n <= 0 {
				acc.buildErrs++
				break
			}
			payloads[built] = buf[:n]
			pktLen[built], pktClass[built] = n, class
			built++
		}
		if built == 0 {
			// Nothing could be built. Report it the way SendFunc does when its
			// callback fails, so the caller's exhaustion handling is the same
			// on both paths rather than spinning on an empty batch.
			return 0, errNothingBuilt
		}
		sent, err := xsk.SendBatch(payloads[:built])
		if err != nil {
			return 0, err
		}
		// SendBatch takes whole packets and may take fewer than offered when
		// the ring is short of room, so count what went rather than what was
		// built.
		for i := range sent {
			acc.add(pktLen[i], pktClass[i])
		}
		return sent, nil
	}
}

// rxLoop is one queue's receive loop, running only when a receive mode is
// enabled. It owns this socket's receive side exclusively.
//
// The per-packet work is deliberately tiny: a length and a three-way protocol
// classification from fixed header offsets. Anything more belongs outside the
// dataplane.
func (r *Runner) rxLoop(ctx context.Context, queue int, xsk *afxdp.Socket) {
	ctr := r.collector.Queue(queue)
	el := newErrLog(r.logf)

	for {
		if ctx.Err() != nil {
			return
		}
		// Hand the kernel buffers to receive into before asking for packets.
		xsk.Fill(xsk.NumFreeFillSlots())

		n, err := xsk.Poll(rxPollTimeout)
		if err != nil {
			if closedSocket(err) || ctx.Err() != nil {
				return
			}
			ctr.RxErrors.Add(1)
			el.printf("queue %d: receive: %v", queue, err)
			continue
		}
		if n == 0 {
			continue
		}

		// ReceivePackets rather than Receive, always. Receive hands back one
		// descriptor per *frame*, so a chained jumbo packet would be counted as
		// several undersized ones with headers on only the first. Grouping is
		// free when nothing chains: with multi-buffer off every packet has
		// exactly one fragment. The two must not be mixed on one socket either,
		// since ReceivePackets carries partial-chain state between calls.
		pkts := xsk.ReceivePackets(n)
		for _, p := range pkts {
			if len(p) == 0 {
				continue
			}
			// Length is the whole packet, and only the first fragment carries
			// the headers Classify reads.
			ctr.AddRx(uint64(p.Len()+fcsLen), generator.Classify(xsk.GetFrame(p[0])))
		}
		xsk.RecyclePackets(pkts)
	}
}

// txStall tracks how long a queue has gone without queueing a packet, which is
// what separates a ring the kernel is busy draining from one nothing is
// draining at all.
//
// It reads the clock only while a stall is in progress. A loop transmitting
// normally never calls backoff, and clear never looks at the time, so the
// success path stays off the clock entirely.
type txStall struct {
	since time.Time
	now   func() time.Time
}

func newTxStall() *txStall { return &txStall{now: time.Now} }

// backoff records a batch that queued nothing and reports whether the queue has
// been stuck long enough to be worth sleeping on. False means retry now.
func (s *txStall) backoff() bool {
	if s.since.IsZero() {
		s.since = s.now()
		return false
	}
	return !s.now().Before(s.since.Add(txStallAfter))
}

// clear forgets a stall in progress, so the next one starts its own budget.
func (s *txStall) clear() { s.since = time.Time{} }

// sleeper is a reusable timer, so a worker that waits thousands of times a
// second for rate credit still allocates nothing.
type sleeper struct{ t *time.Timer }

func newSleeper() *sleeper {
	t := time.NewTimer(time.Hour)
	if !t.Stop() {
		<-t.C
	}
	return &sleeper{t: t}
}

// sleep waits for d, or until ctx is cancelled. It reports whether the wait
// completed normally; false means the caller should return.
func (s *sleeper) sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	s.t.Reset(d)
	select {
	case <-s.t.C:
		return true
	case <-ctx.Done():
		if !s.t.Stop() {
			<-s.t.C
		}
		return false
	}
}

func (s *sleeper) stop() {
	if !s.t.Stop() {
		select {
		case <-s.t.C:
		default:
		}
	}
}

// errLog prints at most one message a second, counting what it suppressed.
//
// A dataplane loop can fail millions of times a second. Neither crashing nor
// logging unbounded is acceptable there, and one instance per goroutine means
// no locking either.
type errLog struct {
	logf       func(string, ...any)
	last       time.Time
	suppressed int
}

func newErrLog(logf func(string, ...any)) *errLog { return &errLog{logf: logf} }

func (e *errLog) printf(format string, args ...any) {
	if time.Since(e.last) < time.Second {
		e.suppressed++
		return
	}
	if e.suppressed > 0 {
		format += " (+%d more suppressed)"
		args = append(args, e.suppressed)
	}
	e.logf(format, args...)
	e.last = time.Now()
	e.suppressed = 0
}
