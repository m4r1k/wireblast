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
