package dataplane

import (
	"fmt"
	"runtime"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
)

// mlx5QueuesPerWorker is how many send queues one worker drives. One: since
// packetio started backing each transmit queue with its own fan-out of
// hardware rings, a queue keeps a whole worker busy by itself, and one
// worker per queue is the arrangement the backend is tuned for. (It used to
// be four, when a single send queue capped near 17 Mpps; a worker driving
// four of today's queues measures the same ~39 Mpps as driving one, from
// one core instead of four queues' worth of hardware.)
const mlx5QueuesPerWorker = 1

// mlx5PerCore is what one worker sustains, in Mpps, at a given frame size.
//
// Measured on a ConnectX-6 Dx behind an EPYC 9275F, one worker driving four
// send queues, each point the whole-machine core accounting of a real run.
// Two things shape the curve. Below the cliff the packet is copied into the
// descriptor, so the cost rises with its size — about 0.8 cycles a byte. Above
// it the packet no longer fits and the card fetches it instead, which costs a
// flat ~425 cycles however big it is. The cliff is between 196 and 200 bytes,
// where the packet stops fitting the inline data segment.
//
// The figures are the measured single-worker rates shaded down, for two
// reasons. A worker sharing the card with others runs slower than one alone —
// 20.0 Mpps at 196 bytes becomes 18.2 once three are running. And a run's
// per-packet cost is settled by an allocation lottery at startup: identical
// runs on identical CPUs measure 136 to 155 cycles a packet (instructions
// flat, IPC 5.4 to 4.8), depending on where that run's flow templates and
// rings landed in physical memory. The table therefore carries the measured
// WORST run, not the typical one: sizing from the good mode gave four
// workers at 68 bytes, and one run in three missed line rate by 10%.
// Rounding down costs a core when the estimate is pessimistic; missing the
// wire on scheduler luck costs the default its whole point.
//
// This is one machine's curve, so it is a starting point rather than a law:
// a different card or clock moves the numbers, and being a core out either way
// costs a core. --queues overrides the arithmetic it feeds, and what was
// chosen is printed at startup.
var mlx5PerCore = []struct {
	frame int     // bytes on the wire, including the FCS: what --packet-size means
	mpps  float64 // one worker's rate at that size
}{
	{68, 33.0}, // best runs do 35.4; the worst measured 31.3, and 33 sizes for it
	{128, 31.0},
	{160, 25.5},
	{196, 18.0},
	{200, 11.0}, // the inline cliff
	{1518, 10.5},
}

// mlx5RxPerCore is what one worker sustains on the RECEIVE side, in Mpps, at
// a given frame size -- a different curve from [mlx5PerCore], and the reason
// a receiving run is sized separately.
//
// Receive costs more per core than transmit and gets worse as workers are
// added, because they contend for the same card rather than each driving
// their own send queues. Measured on a ConnectX-6 Dx under a 148.8 Mpps
// flood of 64-byte frames, whole-machine cores: one worker takes 45.4 Mpps,
// two 38.4 each, four 28.6, six 20.0, eight 18.2, ten 14.7 -- line rate at
// ten workers (148.79 of 148.8 offered, twice), 99% of it at eight.
//
// The figures below are the eight-to-ten-worker end of that curve, which is
// the part that decides whether a 100G receive reaches the wire; sizing from
// the single-worker rate would ask for four workers and take 114.
var mlx5RxPerCore = []struct {
	frame int
	mpps  float64
}{
	{68, 14.9},
	{128, 12.0},
	{512, 6.0},
	{1518, 2.5},
}

// mlx5CoreRate interpolates [mlx5PerCore] at a frame size, clamped at both
// ends.
func mlx5CoreRate(frame int) float64 {
	t := mlx5PerCore
	if frame <= t[0].frame {
		return t[0].mpps
	}
	for i := 1; i < len(t); i++ {
		if frame > t[i].frame {
			continue
		}
		lo, hi := t[i-1], t[i]
		f := float64(frame-lo.frame) / float64(hi.frame-lo.frame)
		return lo.mpps + f*(hi.mpps-lo.mpps)
	}
	return t[len(t)-1].mpps
}

// mlx5RxCoreRate is [mlx5CoreRate] for the receive curve.
func mlx5RxCoreRate(frame int) float64 {
	t := mlx5RxPerCore
	if frame <= t[0].frame {
		return t[0].mpps
	}
	for i := 1; i < len(t); i++ {
		if frame > t[i].frame {
			continue
		}
		lo, hi := t[i-1], t[i]
		f := float64(frame-lo.frame) / float64(hi.frame-lo.frame)
		return lo.mpps + f*(hi.mpps-lo.mpps)
	}
	return t[len(t)-1].mpps
}

// maxAutoQueues bounds what the arithmetic below may ask for on its own. A
// wrong link speed or a very small frame should cost a few queues, not
// hundreds; anything past this is a deliberate --queues.
const maxAutoQueues = 64

// chooseBackend resolves cfg.IO to a concrete backend, and says why.
//
// "auto" prefers Direct Verbs on a ConnectX card. For a transmit-only run the
// two backends are behaviourally identical and mlx5 is several times cheaper
// per packet. For a receiving run mlx5 steers in hardware, which costs nothing
// per packet and leaves unmatched traffic with the kernel — but a mode that is
// an exclusion (keep-management) cannot be expressed as steering rules, and
// such a run stays on AF_XDP rather than quietly taking more than it asked.
func chooseBackend(cfg *config.Config, res *discovery.Resolved, plan FilterPlan) (io, why string) {
	switch cfg.IO {
	case "afxdp", "mlx5":
		return cfg.IO, ""
	}
	switch {
	case !mlx5Available:
		return "afxdp", "this build has no mlx5 backend"
	case res.Link.Driver != "mlx5_core":
		return "afxdp", fmt.Sprintf("driver is %s, not mlx5_core", orUnknown(res.Link.Driver))
	case plan.HardwareUnsupported != "":
		return "afxdp", "--rx-mode " + string(cfg.RxMode) + " needs an XDP program"
	case !mlx5Usable():
		return "afxdp", "no rdma device nodes present"
	}
	if plan.Receives() {
		return "mlx5", "ConnectX card, filter steered in hardware"
	}
	return "mlx5", "ConnectX card, transmit only"
}

func orUnknown(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// autoQueues decides how many queues to open and how many one worker drives.
//
// The two backends want opposite things. AF_XDP must bind every receive queue
// the NIC has, or traffic lands on a queue with no socket behind it, and its
// per-queue work runs in that queue's own soft interrupt, so one worker per
// queue is the only arrangement that helps. mlx5 creates its own queues, so
// the count is ours to pick: enough workers to cover line rate, and enough
// queues each to keep a worker busy.
func autoQueues(io string, cfg *config.Config, link discovery.Link, maxFrame int, receives bool) (queues, perWorker int, why string) {
	perWorker = cfg.QueuesPerWorker
	if io != "mlx5" {
		// One queue per worker, and every queue the device has.
		queues = link.RxQueues
		if cfg.Queues > 0 && cfg.Queues < queues {
			queues = cfg.Queues
		}
		return max(queues, 1), 1, ""
	}

	if perWorker < 1 {
		perWorker = mlx5QueuesPerWorker
		if cfg.PCAPFile != "" {
			// A one-pass replay is paced and ordered per queue; sharing a
			// worker between queues would interleave it.
			perWorker = 1
		}
	}
	if cfg.Queues > 0 {
		return cfg.Queues, perWorker, ""
	}

	workers, why := autoWorkers(link.SpeedMbps, maxFrame, receives)
	queues = workers * perWorker
	if queues > maxAutoQueues {
		queues = maxAutoQueues
	}
	return max(queues, 1), perWorker, why
}

// autoWorkers is how many cores it takes to fill the link, from the line rate
// at this frame size and what one worker was measured to do.
func autoWorkers(speedMbps, frameLen int, receives bool) (int, string) {
	cpus := max(runtime.NumCPU(), 1)
	rate, side := mlx5CoreRate, "transmit"
	if receives {
		// A receiving run is sized from the receive curve, which is the
		// expensive one: filling 100G takes ten workers where transmitting
		// takes four, and sizing receive from the transmit curve is what
		// made a bare receive run stop at 114 of 148.8 Mpps.
		rate, side = mlx5RxCoreRate, "receive"
	}
	if speedMbps <= 0 || frameLen <= 0 {
		// No carrier, or a device that reports no speed. Assume 100G: four
		// workers fill it transmitting, ten receiving.
		n := 4
		if receives {
			n = 10
		}
		return min(n, cpus), "link speed unknown, assuming 100G"
	}
	// On the wire each frame also carries the preamble, the start-of-frame
	// delimiter and the interframe gap: 20 bytes that cost time but are not
	// in the frame.
	lineMpps := float64(speedMbps) / float64((frameLen+20)*8)
	workers := int(lineMpps/rate(frameLen)) + 1
	if workers > cpus {
		workers = cpus
	}
	return max(workers, 1), fmt.Sprintf("sized for %s %s at %d-byte frames", speedLabel(speedMbps), side, frameLen)
}

func speedLabel(mbps int) string {
	if mbps >= 1000 && mbps%1000 == 0 {
		return fmt.Sprintf("%dG", mbps/1000)
	}
	return fmt.Sprintf("%dM", mbps)
}
