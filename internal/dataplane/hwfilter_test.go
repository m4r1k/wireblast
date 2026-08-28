package dataplane

import (
	"strings"
	"testing"

	"github.com/atoonk/packetio"
	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
)

// The hardware filter has to say the same thing the XDP matches say. These
// check each receive mode's translation without a NIC.

func kinds(f packetio.SteeringFilter) map[packetio.MatchKind]int {
	out := map[packetio.MatchKind]int{}
	for _, m := range f.Match {
		out[m.Kind]++
	}
	return out
}

func TestHardwareFilterForPorts(t *testing.T) {
	cfg := &config.Config{Interface: "eth0", VLAN: 2053, RxMode: config.RxUDPPort,
		RxPorts: []uint16{9001, 9005}, Mode: config.ModeUDP}
	plan, err := DefaultFilterBuilder{}.Plan(cfg, &discovery.Resolved{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	k := kinds(plan.Steering)
	if k[packetio.MatchKindVLAN] != 1 {
		t.Errorf("VLAN matches: %d, want 1 (the run's VLAN is part of every filter)", k[packetio.MatchKindVLAN])
	}
	// One alternative per port, each carrying its protocol.
	if k[packetio.MatchKindDstPort] != 2 || k[packetio.MatchKindIPProto] != 2 {
		t.Errorf("port %d / proto %d matches, want 2 / 2", k[packetio.MatchKindDstPort], k[packetio.MatchKindIPProto])
	}
	if err := plan.Steering.Validate(); err != nil {
		t.Errorf("the plan's own filter does not validate: %v", err)
	}
	if plan.HardwareUnsupported != "" {
		t.Errorf("udp-port marked unsupported: %s", plan.HardwareUnsupported)
	}
	// TCP ports carry the TCP protocol, not UDP.
	cfg.RxMode = config.RxTCPPort
	plan, _ = DefaultFilterBuilder{}.Plan(cfg, &discovery.Resolved{})
	for _, m := range plan.Steering.Match {
		if m.Kind == packetio.MatchKindDstPort && m.IPProto != packetio.IPProtoTCP {
			t.Errorf("tcp-port produced a port match with protocol %d", m.IPProto)
		}
	}
}

func TestHardwareFilterForCIDRAndAll(t *testing.T) {
	cfg := &config.Config{Interface: "eth0", RxMode: config.RxCIDR, RxCIDR: "10.0.0.0/8"}
	plan, err := DefaultFilterBuilder{}.Plan(cfg, &discovery.Resolved{})
	if err != nil {
		t.Fatalf("cidr: %v", err)
	}
	if kinds(plan.Steering)[packetio.MatchKindSrcIP] != 1 {
		t.Errorf("cidr did not produce a source-prefix match: %v", plan.Steering)
	}
	// No VLAN configured, so no VLAN match: the filter must not invent one.
	if kinds(plan.Steering)[packetio.MatchKindVLAN] != 0 {
		t.Error("a VLAN match appeared with no VLAN configured")
	}

	cfg = &config.Config{Interface: "eth0", RxMode: config.RxAll, AllowMatchAll: true}
	plan, err = DefaultFilterBuilder{}.Plan(cfg, &discovery.Resolved{})
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if !plan.Steering.Promiscuous {
		t.Error("--rx-mode all did not become a promiscuous filter")
	}
}

func TestKeepManagementIsXDPOnly(t *testing.T) {
	cfg := &config.Config{Interface: "eth0", RxMode: config.RxKeepManagement}
	plan, err := DefaultFilterBuilder{}.Plan(cfg, &discovery.Resolved{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	// An exclusion has no hardware form. The plan says so, and says what to
	// use instead, because that is what the user reads.
	if plan.HardwareUnsupported == "" {
		t.Fatal("keep-management has no HardwareUnsupported reason")
	}
	if !strings.Contains(plan.HardwareUnsupported, "udp-port") {
		t.Errorf("the reason does not point at an alternative: %q", plan.HardwareUnsupported)
	}
	if len(plan.Steering.Match) != 0 || plan.Steering.Promiscuous {
		t.Errorf("keep-management produced a hardware filter anyway: %v", plan.Steering)
	}

	// Auto must not pick mlx5 for it, whatever the card.
	res := &discovery.Resolved{Link: discovery.Link{Driver: "mlx5_core"}}
	if io, why := chooseBackend(&config.Config{IO: "auto", RxMode: config.RxKeepManagement}, res, plan); io != "afxdp" || why == "" {
		t.Errorf("auto chose %s (%q) for keep-management", io, why)
	}
}

func TestExplicitMLX5RefusesKeepManagement(t *testing.T) {
	// --io mlx5 with an XDP-only mode is a configuration error the user must
	// see, not a filter that quietly takes everything.
	cfg := &config.Config{Interface: "eth0", IO: "mlx5", RxMode: config.RxKeepManagement,
		Mode: config.ModeReceive}
	res := &discovery.Resolved{Link: discovery.Link{Name: "eth0", Driver: "mlx5_core", RxQueues: 4, MTU: 1500}}
	_, err := New(cfg, res, Options{})
	if err == nil {
		t.Fatal("New accepted --io mlx5 with --rx-mode keep-management")
	}
	if !strings.Contains(err.Error(), "keep-management") {
		t.Errorf("error does not name the mode: %v", err)
	}
}

// The two backends install different filters from the same flags, because the
// XDP program has no VLAN match and hardware steering does. That is a real
// difference in what gets captured, so the plan has to admit it rather than let
// the user believe the AF_XDP filter is as narrow as the mlx5 one.
func TestAFXDPFilterAdmitsItIgnoresTheVLAN(t *testing.T) {
	for _, mode := range []struct {
		name string
		cfg  *config.Config
	}{
		{"udp-port", &config.Config{Interface: "eth0", VLAN: 2053, RxMode: config.RxUDPPort,
			RxPorts: []uint16{9001}, Mode: config.ModeUDP}},
		{"cidr", &config.Config{Interface: "eth0", VLAN: 2053, RxMode: config.RxCIDR,
			RxCIDR: "198.51.100.0/24", Mode: config.ModeUDP}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			p, err := DefaultFilterBuilder{}.Plan(mode.cfg, &discovery.Resolved{})
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			var said bool
			for _, l := range p.Limitations {
				if strings.Contains(l, "VLAN id is not matched") && strings.Contains(l, "2053") {
					said = true
				}
			}
			if !said {
				t.Errorf("no limitation says the AF_XDP filter ignores the VLAN:\n%v", p.Limitations)
			}
			// The hardware filter still matches it; that is the difference.
			if k := kinds(p.Steering); k[packetio.MatchKindVLAN] != 1 {
				t.Errorf("hardware filter has %d VLAN matches, want 1", k[packetio.MatchKindVLAN])
			}
		})
	}
}

// --rx-mode all is promiscuous on both backends, so there is no narrowing to
// misrepresent and the note would be noise.
func TestNoVLANNoteForPromiscuous(t *testing.T) {
	cfg := &config.Config{Interface: "eth0", VLAN: 2053, RxMode: config.RxAll,
		Mode: config.ModeUDP, AllowMatchAll: true}
	p, err := DefaultFilterBuilder{}.Plan(cfg, &discovery.Resolved{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, l := range p.Limitations {
		if strings.Contains(l, "VLAN id is not matched") {
			t.Errorf("promiscuous plan warned about VLAN matching: %q", l)
		}
	}
}

// A run that is not receiving has no filter to be wrong about.
func TestNoVLANNoteWhenNotReceiving(t *testing.T) {
	cfg := &config.Config{Interface: "eth0", VLAN: 2053, RxMode: config.RxNone, Mode: config.ModeUDP}
	p, err := DefaultFilterBuilder{}.Plan(cfg, &discovery.Resolved{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, l := range p.Limitations {
		if strings.Contains(l, "VLAN id is not matched") {
			t.Errorf("transmit-only run warned about receive filtering: %q", l)
		}
	}
}

// vlanRegistered is what decides whether the preflight refuses an AF_XDP
// receive on a tagged interface, so it has to agree with what the kernel would
// actually accept: a sub-interface for this id, on this parent.
func TestVLANRegistered(t *testing.T) {
	parent := discovery.Link{Name: "eno2", Index: 3}
	other := discovery.Link{Name: "eno1", Index: 2}
	links := []discovery.Link{
		parent, other,
		{Name: "eno2.2043", Index: 9, VLANID: 2043, ParentIndex: 3},
		{Name: "eno1.2053", Index: 10, VLANID: 2053, ParentIndex: 2}, // right id, wrong parent
	}
	if vlanRegistered(links, parent, 2053) {
		t.Error("2053 reported as registered on eno2; the only 2053 is on eno1")
	}
	if !vlanRegistered(links, parent, 2043) {
		t.Error("2043 is registered on eno2 and was not found")
	}
	if vlanRegistered(nil, parent, 2053) {
		t.Error("found a VLAN among no links")
	}
}

// Binding fewer queues than the card has is the second way an AF_XDP receive
// silently gets nothing: the card hashes a flow to one queue, and a queue with
// no socket goes to the kernel. Measured on a 48-queue ConnectX -- four queues
// received nothing of 200 kpps, forty-eight received all of it.
func TestPreflightWarnsOnPartialQueueBinding(t *testing.T) {
	link := discovery.Link{Name: "eno2", Index: 3, RxQueues: 48, Up: true, Carrier: true,
		MAC: []byte{2, 0, 0, 0, 0, 1}, Driver: "mlx5_core", MTU: 1500}
	in := PreflightInput{
		Cfg:     &config.Config{Interface: "eno2", RxMode: config.RxUDPPort, RxPorts: []uint16{9000}},
		Res:     &discovery.Resolved{Link: link},
		Plan:    FilterPlan{receives: true},
		Backend: "afxdp",
		Queues:  4,
	}
	var found *Check
	for i, c := range RunPreflight(in).Checks {
		if strings.Contains(c.Title, "queues") {
			found = &RunPreflight(in).Checks[i]
		}
	}
	if found == nil {
		t.Fatal("no warning about binding 4 of 48 queues")
	}
	for _, want := range []string{"48", "4", "--queues 48"} {
		if !strings.Contains(found.Detail+found.Fix, want) {
			t.Errorf("the warning does not mention %q:\n%s\n%s", want, found.Detail, found.Fix)
		}
	}

	// Binding all of them is the normal case and must be silent.
	in.Queues = 48
	for _, c := range RunPreflight(in).Checks {
		if strings.Contains(c.Title, "queues") {
			t.Errorf("warned when binding every queue: %s", c.Detail)
		}
	}

	// So is a transmit-only run, which receives nothing by definition.
	in.Queues = 4
	in.Plan = FilterPlan{}
	for _, c := range RunPreflight(in).Checks {
		if strings.Contains(c.Title, "queues") {
			t.Errorf("warned a transmit-only run about receive queues: %s", c.Detail)
		}
	}
}
