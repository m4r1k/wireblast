package dataplane

import (
	"os/exec"
	"strings"

	"github.com/atoonk/wireblast/internal/discovery"
)

// vlanFilterOn reports whether the interface asks the card to drop VLAN ids the
// kernel has not registered, and whether that could be determined at all.
//
// This is the mlx5e default and it is invisible until it costs an afternoon: a
// tagged frame whose id nothing has registered is dropped in the card's own
// flow table, before the XDP hook. The program never runs, the filter never
// matches, and the only symptom is a receive run reporting zero packets with no
// error to be found anywhere.
//
// An interface that does not report the feature -- most virtual devices -- is
// "not known", and the caller says nothing rather than guessing.
func vlanFilterOn(iface string) (on, known bool) {
	if iface == "" || strings.ContainsAny(iface, "/ \x00") {
		return false, false
	}
	// Read-only, and it runs before a preflight refusal, so it must not be able
	// to change anything. -k prints the feature list; there is no -K here.
	out, err := exec.Command("ethtool", "-k", iface).Output()
	if err != nil {
		return false, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) != "rx-vlan-filter" {
			continue
		}
		// "on", "off", or either with " [fixed]" after it.
		return strings.HasPrefix(strings.TrimSpace(value), "on"), true
	}
	return false, false
}

// vlanRegistered reports whether anything has told the kernel about this VLAN id
// on this link, which is what makes the card pass frames carrying it.
//
// A sub-interface is the usual way. The links have already been read for the
// preflight, so this walks them rather than going back to netlink.
func vlanRegistered(all []discovery.Link, parent discovery.Link, vlanID int) bool {
	for _, l := range all {
		if l.VLANID == vlanID && l.ParentIndex == parent.Index {
			return true
		}
	}
	return false
}
