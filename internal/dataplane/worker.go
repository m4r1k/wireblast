package dataplane

import (
	"context"
	"errors"
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

	pacer, paced := gen.(generator.Pacer)
	finite, isFinite := gen.(generator.Finite)
	avgWire := gen.AvgWireBytes()

	// Per-batch accumulators, declared once so the closures below capture
	// stack slots rather than allocating each time round.
	var (
		bytes     uint64
		clsPkts   [3]int
		clsBytes  [3]uint64
		buildErrs int
		// owed is unslept capture time accumulated in original-timing mode.
		owed time.Duration
	)

	// count folds one built packet into the accumulators. The FCS the NIC will
	// append is included, so byte totals and average frame sizes are in the
	// same units as --packet-size.
	count := func(n int, class stats.Class) {
		bytes += uint64(n + fcsLen)
		clsPkts[class]++
		clsBytes[class] += uint64(n + fcsLen)
	}

	// send builds and queues up to want packets, returning how many the kernel
	// took. Which implementation runs is decided once, here, rather than per
	// batch.
	batchCap, send := r.sender(xsk, gen, count, &buildErrs)

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
				if !sleeper.sleep(ctx, owed) {
					return
				}
				owed = 0
			}
		}

		grant, wait := r.limiter.Acquire(want, avgWire)
		if grant.Packets == 0 {
			if !sleeper.sleep(ctx, wait) {
				return
			}
			continue
		}

		bytes = 0
		clsPkts = [3]int{}
		clsBytes = [3]uint64{}
		buildErrs = 0

		sent, err := send(grant.Packets)

		switch {
		case err != nil && closedSocket(err):
			return // the socket was closed under us during shutdown
		case err != nil:
			// Nothing was queued, so none of the accumulated counts happened.
			ctr.TxErrors.Add(1)
			r.limiter.Settle(grant, 0, 0)
			if buildErrs == 0 {
				el.printf("queue %d: transmit: %v", queue, err)
			}
			if buildErrs > 0 {
				return // the generator is exhausted mid-batch; this queue is done
			}
			continue
		}

		for c := range clsPkts {
			if clsPkts[c] > 0 {
				ctr.AddTx(clsPkts[c], clsBytes[c], stats.Class(c))
			}
		}
		r.limiter.Settle(grant, sent, bytes+uint64(sent)*wireOverhead)

		if sent == 0 {
			// The ring was momentarily full. SendFunc already kicked the
			// kernel; yield briefly rather than spinning on it.
			if !sleeper.sleep(ctx, 50*time.Microsecond) {
				return
			}
		}
	}
}

// sender picks how this run puts packets on the wire and returns the batch
// size that goes with it. count is called for every packet the kernel accepts;
// buildErrs is incremented when the generator has nothing left to give.
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
	count func(int, stats.Class),
	buildErrs *int,
) (int, func(want int) (int, error)) {
	if !r.multiBuffer {
		return txBatch, func(want int) (int, error) {
			return xsk.SendFunc(want, func(_ int, frame []byte) int {
				n, class := gen.Next(frame)
				if n <= 0 {
					// A generator with nothing left. Returning 0 would put an
					// empty frame on the wire, so report it as a build failure:
					// SendFunc abandons the whole batch unqueued.
					*buildErrs++
					return -1
				}
				count(n, class)
				return n
			})
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
				*buildErrs++
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
			count(pktLen[i], pktClass[i])
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
