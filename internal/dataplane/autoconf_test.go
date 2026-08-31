package dataplane

import (
	"runtime"
	"testing"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
)

func TestAutoWorkers(t *testing.T) {
	cpus := runtime.NumCPU()
	tests := []struct {
		name         string
		speed, frame int
		want         int
	}{
		// Each of these is a measured run: the worker count is the smallest
		// that reached line rate on the rig at that frame size.
		{"100G 68-byte", 100000, 68, 5}, // sized for the worst measured run, so every run reaches the wire
		{"100G 128-byte", 100000, 128, 3},
		{"100G 256-byte", 100000, 256, 5}, // past the inline cliff
		{"100G 512-byte", 100000, 512, 3},
		{"100G jumbo", 100000, 1500, 1},
		// Twice the link needs twice the workers. Extrapolated, not measured:
		// the rig has no 200G card.
		{"200G 68-byte", 200000, 68, 9},
		{"10G small", 10000, 68, 1},
		// No carrier, or a device that reports no speed at all.
		{"unknown speed", 0, 68, 4},
		{"unknown frame", 100000, 0, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, why := autoWorkers(tt.speed, tt.frame, false)
			want := min(tt.want, cpus)
			if got != want {
				t.Errorf("autoWorkers(%d, %d) = %d, want %d", tt.speed, tt.frame, got, want)
			}
			if why == "" {
				t.Error("autoWorkers gave no reason")
			}
		})
	}
}

// TestMLX5CoreRate checks the interpolation, not the measurements: that it
// clamps at both ends, reproduces the table exactly at its own points, and
// falls monotonically in between.
func TestMLX5CoreRate(t *testing.T) {
	for _, p := range mlx5PerCore {
		if got := mlx5CoreRate(p.frame); got != p.mpps {
			t.Errorf("mlx5CoreRate(%d) = %g, want the table's %g", p.frame, got, p.mpps)
		}
	}
	first, last := mlx5PerCore[0], mlx5PerCore[len(mlx5PerCore)-1]
	if got := mlx5CoreRate(1); got != first.mpps {
		t.Errorf("below the table: got %g, want %g", got, first.mpps)
	}
	if got := mlx5CoreRate(9000); got != last.mpps {
		t.Errorf("above the table: got %g, want %g", got, last.mpps)
	}
	prev := mlx5CoreRate(1)
	for f := 2; f <= 9000; f++ {
		got := mlx5CoreRate(f)
		if got > prev {
			t.Fatalf("mlx5CoreRate rose at %d bytes: %g after %g", f, got, prev)
		}
		if got <= 0 {
			t.Fatalf("mlx5CoreRate(%d) = %g", f, got)
		}
		prev = got
	}
}

func TestAutoWorkersNeverExceedsCPUs(t *testing.T) {
	// An implausibly fast link must not ask for more workers than there are
	// cores to run them on.
	got, _ := autoWorkers(8_000_000, 64, false)
	if got > runtime.NumCPU() {
		t.Errorf("autoWorkers = %d, more than %d CPUs", got, runtime.NumCPU())
	}
}

// TestAutoWorkersReceiveIsBigger pins the reason the receive curve exists: a
// receiving run on the same link and frame size must ask for more workers
// than a transmitting one, because receive costs more per core. Sizing
// receive from the transmit curve asked for four workers and took 114 of
// 148.8 Mpps; ten is what reaches the wire.
func TestAutoWorkersReceiveIsBigger(t *testing.T) {
	cpus := runtime.NumCPU()
	tx, _ := autoWorkers(100000, 68, false)
	rx, _ := autoWorkers(100000, 68, true)
	if want := min(10, cpus); rx != want {
		t.Errorf("receive workers = %d, want %d", rx, want)
	}
	if cpus >= 10 && rx <= tx {
		t.Errorf("receive %d workers is not more than transmit %d", rx, tx)
	}
	// An unknown link speed assumes 100G on both sides, and the same asymmetry.
	if got, _ := autoWorkers(0, 68, true); got != min(10, cpus) {
		t.Errorf("unknown speed receive = %d, want %d", got, min(10, cpus))
	}
}

func TestAutoQueuesAFXDP(t *testing.T) {
	link := discovery.Link{RxQueues: 12, SpeedMbps: 100000}

	// AF_XDP binds every receive queue, one worker each, whatever the link
	// speed says.
	q, per, _ := autoQueues("afxdp", &config.Config{}, link, 64, false)
	if q != 12 || per != 1 {
		t.Errorf("got %d queues, %d per worker; want 12, 1", q, per)
	}

	// --queues caps it, and never raises it past what the device has.
	if q, _, _ := autoQueues("afxdp", &config.Config{Queues: 4}, link, 64, false); q != 4 {
		t.Errorf("--queues 4: got %d, want 4", q)
	}
	if q, _, _ := autoQueues("afxdp", &config.Config{Queues: 99}, link, 64, false); q != 12 {
		t.Errorf("--queues 99: got %d, want 12", q)
	}

	// A device that reports no queues still gets one.
	if q, _, _ := autoQueues("afxdp", &config.Config{}, discovery.Link{}, 64, false); q != 1 {
		t.Errorf("no queues: got %d, want 1", q)
	}
}

func TestAutoQueuesMLX5(t *testing.T) {
	link := discovery.Link{RxQueues: 48, SpeedMbps: 100000}
	cfg := &config.Config{}
	// autoWorkers never asks for more workers than there are cores, so the
	// expectations here carry the same clamp as the rest of this file.
	workers := min(5, runtime.NumCPU())

	// The NIC's own queue count is irrelevant: mlx5 creates its own, and the
	// count comes from line rate — five workers at 68 bytes, sized for the
	// worst measured run.
	q, per, why := autoQueues("mlx5", cfg, link, 68, false)
	if want := workers * mlx5QueuesPerWorker; q != want || per != mlx5QueuesPerWorker {
		t.Errorf("got %d queues, %d per worker; want %d, %d", q, per, want, mlx5QueuesPerWorker)
	}
	if why == "" {
		t.Error("no sizing reason")
	}

	// Either flag overrides its half of the arithmetic.
	if q, per, _ := autoQueues("mlx5", &config.Config{Queues: 7}, link, 68, false); q != 7 || per != mlx5QueuesPerWorker {
		t.Errorf("--queues 7: got %d, %d", q, per)
	}
	if q, per, _ := autoQueues("mlx5", &config.Config{QueuesPerWorker: 2}, link, 68, false); per != 2 || q != workers*2 {
		t.Errorf("--queues-per-worker 2: got %d queues, %d per worker; want %d, 2", q, per, workers*2)
	}

	// A replay is paced and ordered per queue, so it keeps one queue per
	// worker even on mlx5.
	if _, per, _ := autoQueues("mlx5", &config.Config{PCAPFile: "x.pcap"}, link, 68, false); per != 1 {
		t.Errorf("pcap: got %d per worker, want 1", per)
	}

	// The derived count is bounded however fast the link claims to be.
	if q, _, _ := autoQueues("mlx5", cfg, discovery.Link{SpeedMbps: 8_000_000}, 64, false); q > maxAutoQueues {
		t.Errorf("got %d queues, more than the %d cap", q, maxAutoQueues)
	}
}

func TestChooseBackendExplicit(t *testing.T) {
	res := &discovery.Resolved{Link: discovery.Link{Driver: "mlx5_core"}}
	for _, io := range []string{"afxdp", "mlx5"} {
		got, why := chooseBackend(&config.Config{IO: io}, res, FilterPlan{})
		if got != io {
			t.Errorf("--io %s: got %s", io, got)
		}
		if why != "" {
			t.Errorf("--io %s: explained an explicit choice: %q", io, why)
		}
	}
}

func TestChooseBackendAuto(t *testing.T) {
	mlx5 := &discovery.Resolved{Link: discovery.Link{Driver: "mlx5_core"}}
	other := &discovery.Resolved{Link: discovery.Link{Driver: "ixgbe"}}

	// A non-ConnectX card is AF_XDP whatever the build.
	if got, why := chooseBackend(&config.Config{IO: "auto"}, other, FilterPlan{}); got != "afxdp" || why == "" {
		t.Errorf("ixgbe: got %s (%q), want afxdp with a reason", got, why)
	}

	// A receiving run stays on AF_XDP even on a ConnectX card, because its
	// filters are XDP programs.
	got, why := chooseBackend(&config.Config{IO: "auto"}, mlx5, FilterPlan{receives: true})
	if got != "afxdp" || why == "" {
		t.Errorf("receiving: got %s (%q), want afxdp with a reason", got, why)
	}

	// Transmit-only on a ConnectX card: mlx5 if this build has it and the
	// device nodes are there, AF_XDP otherwise. Both answers are correct;
	// what must hold is that the choice is explained either way.
	got, why = chooseBackend(&config.Config{IO: "auto"}, mlx5, FilterPlan{})
	if !mlx5Available && got != "afxdp" {
		t.Errorf("build without mlx5 chose %s", got)
	}
	if got == "afxdp" && why == "" {
		t.Error("fell back to afxdp without saying why")
	}
	if got != "afxdp" && got != "mlx5" {
		t.Errorf("chose %q", got)
	}

	// An empty --io means the same as auto.
	if a, _ := chooseBackend(&config.Config{}, mlx5, FilterPlan{}); a != got {
		t.Errorf("empty --io chose %s, auto chose %s", a, got)
	}
}
