package dataplane

import (
	"time"

	xdp "github.com/atoonk/go-afxdp"
	"github.com/atoonk/packetio"
)

// What the datapath needs from an I/O backend, and nothing more.
//
// wireblast used to hold go-afxdp's own types all the way down. It now holds
// packetio's, so the same transmit and receive loops run over AF_XDP or over
// mlx5 Direct Verbs, chosen with --io. The two verbs sets are the same shape
// because both libraries describe a frame the same way; what differs is
// backend-specific and is reached by asking for it, below.

// txQueue is one transmit queue. packetio.TxQueue satisfies it as it stands.
type txQueue interface {
	SendFunc(count int, build func(i int, frame []byte) int) (int, error)
	Complete(max int) int
	NumCompleted() int
	NumInFlight() int
}

// rxQueue is one receive queue.
type rxQueue interface {
	Fill(n int) int
	Poll(timeout time.Duration) (int, error)
	Region() packetio.Region
}

// batchSender is implemented by a backend that can send a payload spanning
// several frames. Only AF_XDP can, so a jumbo run needs one; a backend without
// it is refused at preflight rather than silently truncating.
type batchSender interface {
	SendBatch(payloads [][]byte) (int, error)
}

// packetReceiver is implemented by a backend that reports a received packet as
// the run of frames it occupies, which is the only way to count jumbo frames
// correctly. Mixing it with a plain Receive on one queue is a mistake: they
// consume the same ring and count differently.
type packetReceiver interface {
	ReceivePackets(maxFrames int) []xdp.Packet
	RecyclePackets(pkts []xdp.Packet)
}

// pinner is implemented by a backend that can place the calling goroutine on
// the processor its queue belongs to. Both backends do; the interface exists so
// the loop does not have to name either of them.
type pinner interface {
	Pin() (int, error)
}

// device is the open NIC. packetio.Device satisfies it.
type device interface {
	NumTxQueues() int
	NumRxQueues() int
	TxQueue(i int) packetio.TxQueue
	RxQueue(i int) packetio.RxQueue
	Capabilities() packetio.Capabilities
	Close() error
}
