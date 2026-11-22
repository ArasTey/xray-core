package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

// The mimic packets are written into the device UAPI by proxy/wireguard, from
// the proto. The JSON layer is what carries them there, and it did not have
// the fields: the app sent mimicPacket1..5, the loader dropped them, and the
// core wrote no i1..i5 at all — the decoys silently did nothing.
func TestMimicPacketsReachTheProto(t *testing.T) {
	peer := &conf.WireGuardPeerConfig{
		PublicKey:    "e4c1b1e5f2e1e5e2c1b1e5f2e1e5e2c1b1e5f2e1e5e2c1b1e5f2e1e5e2c1b1",
		MimicPacket1: "<b 4f5054494f4e73207369702d3a2e2e>",
		MimicPacket2: "<t>",
		MimicPacket3: "<dz 16>",
		MimicPacket4: "<r 8>",
		MimicPacket5: "<rc 8>",
	}

	built, err := peer.Build()
	if err != nil {
		t.Fatal("build failed:", err)
	}

	cases := map[string]string{
		"mimicPacket1": built.GetMimicPacket_1(),
		"mimicPacket2": built.GetMimicPacket_2(),
		"mimicPacket3": built.GetMimicPacket_3(),
		"mimicPacket4": built.GetMimicPacket_4(),
		"mimicPacket5": built.GetMimicPacket_5(),
	}
	want := map[string]string{
		"mimicPacket1": "<b 4f5054494f4e73207369702d3a2e2e>",
		"mimicPacket2": "<t>",
		"mimicPacket3": "<dz 16>",
		"mimicPacket4": "<r 8>",
		"mimicPacket5": "<rc 8>",
	}
	for name, value := range want {
		if cases[name] != value {
			t.Errorf("%s = %q, want %q", name, cases[name], value)
		}
	}
}

// A profile without mimic packets must not grow empty ones: an empty spec
// would be written to the UAPI and the device would reject it.
func TestNoMimicPacketsStayEmpty(t *testing.T) {
	peer := &conf.WireGuardPeerConfig{
		PublicKey: "e4c1b1e5f2e1e5e2c1b1e5f2e1e5e2c1b1e5f2e1e5e2c1b1e5f2e1e5e2c1b1",
	}

	built, err := peer.Build()
	if err != nil {
		t.Fatal("build failed:", err)
	}

	if built.GetMimicPacket_1() != "" || built.GetMimicPacket_5() != "" {
		t.Error("an unset mimic packet must stay empty")
	}
}
