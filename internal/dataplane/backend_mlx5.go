//go:build mlx5

package dataplane

import (
	"fmt"
	"os"

	"github.com/atoonk/packetio"
	"github.com/atoonk/packetio/mlx5"
)

// mlx5Available says this binary was built with the Direct Verbs backend.
//
// It is behind a build tag because that backend needs cgo and rdma-core at
// build and run time, and wireblast's ordinary form is a single static binary
// that runs anywhere. Build it with "-tags mlx5" to get this one.
const mlx5Available = true

// openMLX5 opens the NIC through mlx5 Direct Verbs. There is no XDP program and
// no filter: the card is told by a steering rule what to send to these queues,
// and everything else still reaches the kernel.
func openMLX5(iface string, queues, frameSize, numFrames int, steering packetio.SteeringFilter, transmitOnly bool) (packetio.Device, string, error) {
	opts := []mlx5.Option{
		mlx5.WithTxQueues(queues),
		mlx5.WithFrameSize(frameSize),
	}
	if numFrames > 0 {
		opts = append(opts, mlx5.WithFrames(numFrames))
	}
	if transmitOnly {
		opts = append(opts, mlx5.WithRxQueues(0))
	} else {
		// The card matches the filter in hardware; anything it does not match
		// still reaches the kernel, which is what keeps SSH working.
		opts = append(opts, mlx5.WithRxQueues(queues), mlx5.WithSteering(steering))
	}
	d, err := mlx5.Open(iface, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("mlx5: %w", err)
	}
	installed := ""
	if !transmitOnly {
		installed = d.Info().Steering
	}
	return d, installed, nil
}

// mlx5Usable reports whether the rdma device nodes Direct Verbs needs are
// present. The backend is compiled in, but the kernel modules that expose the
// card to userspace may not be loaded, and "auto" should fall back quietly
// rather than fail the run.
func mlx5Usable() bool {
	ents, err := os.ReadDir("/dev/infiniband")
	return err == nil && len(ents) > 0
}
