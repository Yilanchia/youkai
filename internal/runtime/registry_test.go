package runtime

import (
	"sort"
	"testing"

	"youkai/internal/accounts"
	"youkai/internal/binary"
	"youkai/internal/gate"
	"youkai/internal/web"
	"youkai/internal/whitebox"
)

// TestEveryGatedCapabilityIsReachable is the registry invariant that keeps the
// dispatcher honest:
//
//   - every capability in the gate table is registered by exactly one package,
//     so a name in the UI can never resolve to "no capability named ...";
//   - no name is registered twice, because the dispatcher would silently pick one
//     and the other's tier/implementation would be dead code.
func TestEveryGatedCapabilityIsReachable(t *testing.T) {
	owner := map[string]string{}
	add := func(pkg string, names []string) {
		for _, name := range names {
			if prev, ok := owner[name]; ok {
				t.Errorf("%q is registered by both %s and %s", name, prev, pkg)
				continue
			}
			owner[name] = pkg
		}
	}

	var webNames, binaryNames, accountNames, whiteboxNames []string
	for _, c := range web.Registry() {
		webNames = append(webNames, c.Name)
	}
	for _, c := range binary.Registry() {
		binaryNames = append(binaryNames, c.Name)
	}
	for _, c := range accounts.Registry() {
		accountNames = append(accountNames, c.Name)
	}
	for _, c := range whitebox.Registry() {
		whiteboxNames = append(whiteboxNames, c.Name)
	}
	add("web", webNames)
	add("binary", binaryNames)
	add("accounts", accountNames)
	add("whitebox", whiteboxNames)

	gated := append(gate.ReadOnlyCapabilities(), gate.ProofCapabilities()...)
	sort.Strings(gated)
	for _, name := range gated {
		if _, ok := owner[name]; !ok {
			t.Errorf("capability %q is in the gate table but no package registers it", name)
		}
	}

	// A registered capability the gate does not know is worse than a missing one:
	// it would classify as tier 3 and be permanently unexecutable. Ask the gate.
	for name := range owner {
		if tier := gate.Classify(name, nil); tier == gate.TierDeep {
			t.Errorf("%q is registered but the gate classifies it tier3 (unexecutable)", name)
		}
	}
}

// TestDispatcherHasEveryCapability checks the routing table the engine actually
// uses, including the capability packages that are not web/binary.
func TestDispatcherHasEveryCapability(t *testing.T) {
	d := &Dispatcher{}
	for _, c := range web.Registry() {
		if !d.Has(c.Name) {
			t.Errorf("dispatcher cannot route %q", c.Name)
		}
	}
	for _, c := range binary.Registry() {
		if !d.Has(c.Name) {
			t.Errorf("dispatcher cannot route %q", c.Name)
		}
	}
	for _, c := range accounts.Registry() {
		if !d.Has(c.Name) {
			t.Errorf("dispatcher cannot route %q", c.Name)
		}
	}
	if d.Has("definitely_not_a_capability") {
		t.Fatal("dispatcher routed an unknown name")
	}
}

// TestTiersAgree pins that each package's declared tier equals the gate's answer,
// so the UI badge and the dispatcher's refusal cannot disagree.
func TestTiersAgree(t *testing.T) {
	for pkg, caps := range map[string][]struct {
		Name string
		Tier gate.Tier
	}{
		"web":      toTiered(web.Registry()),
		"binary":   toTieredBinary(binary.Registry()),
		"accounts": toTieredAccounts(accounts.Registry()),
	} {
		for _, c := range caps {
			if got := gate.Classify(c.Name, nil); got != c.Tier {
				t.Errorf("%s: %s tier = %v, gate says %v", pkg, c.Name, c.Tier, got)
			}
		}
	}
}

func toTiered(in []web.Capability) []struct {
	Name string
	Tier gate.Tier
} {
	out := make([]struct {
		Name string
		Tier gate.Tier
	}, 0, len(in))
	for _, c := range in {
		out = append(out, struct {
			Name string
			Tier gate.Tier
		}{c.Name, c.Tier})
	}
	return out
}

func toTieredBinary(in []binary.Capability) []struct {
	Name string
	Tier gate.Tier
} {
	out := make([]struct {
		Name string
		Tier gate.Tier
	}, 0, len(in))
	for _, c := range in {
		out = append(out, struct {
			Name string
			Tier gate.Tier
		}{c.Name, c.Tier})
	}
	return out
}

func toTieredAccounts(in []accounts.Capability) []struct {
	Name string
	Tier gate.Tier
} {
	out := make([]struct {
		Name string
		Tier gate.Tier
	}, 0, len(in))
	for _, c := range in {
		out = append(out, struct {
			Name string
			Tier gate.Tier
		}{c.Name, c.Tier})
	}
	return out
}
