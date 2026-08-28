//go:build !mlx5

package dataplane

import (
	"errors"

	"github.com/atoonk/packetio"
)

// mlx5Available says this binary was built without the Direct Verbs backend,
// which is the ordinary case: it needs cgo and rdma-core, and wireblast's
// default build is a single static binary that runs anywhere.
const mlx5Available = false

func openMLX5(iface string, queues, frameSize, numFrames int, steering packetio.SteeringFilter, transmitOnly bool) (packetio.Device, string, error) {
	return nil, "", errors.New("this build has no mlx5 backend; rebuild with -tags mlx5 (it needs cgo and rdma-core)")
}

// mlx5Usable is never true in a build without the backend.
func mlx5Usable() bool { return false }
