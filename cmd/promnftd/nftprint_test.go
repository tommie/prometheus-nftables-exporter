package main

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/tommie/prometheus-nftables-exporter/udata"
	"golang.org/x/sys/unix"
)

func TestRuleCounter(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		want := &expr.Counter{}

		got := ruleCounter(&nftables.Rule{
			Exprs: []expr.Any{nil, want},
		})

		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("missing", func(t *testing.T) {
		got := ruleCounter(&nftables.Rule{
			Exprs: []expr.Any{},
		})

		if got != nil {
			t.Errorf("got %v, want %v", got, nil)
		}
	})
}

func TestRuleComment(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		want := "test"

		got, err := ruleComment(&nftables.Rule{
			UserData: makeRuleComment(want),
		})

		if err != nil {
			t.Fatalf("failed: %v", err)
		}
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("missing", func(t *testing.T) {
		got, err := ruleComment(&nftables.Rule{})

		if err != nil {
			t.Fatalf("failed: %v", err)
		}
		if got != "" {
			t.Errorf("got %q, want %q", got, "")
		}
	})
}

func makeRuleComment(s string) []byte {
	return append([]byte{byte(udata.RuleComment), byte(len(s) + 1)}, append([]byte(s), '\x00')...)
}

func TestChainPolicyString(t *testing.T) {
	t.Run("defined", func(t *testing.T) {
		p := nftables.ChainPolicyDrop
		got := chainPolicyString(&p)
		want := "drop"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		p := nftables.ChainPolicy(42)
		got := chainPolicyString(&p)
		want := "unknown(42)"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("nil", func(t *testing.T) {
		got := chainPolicyString(nil)
		want := "accept"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestTableFamilyString(t *testing.T) {
	t.Run("defined", func(t *testing.T) {
		got := tableFamilyString(nftables.TableFamilyINet)
		want := "inet"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		got := tableFamilyString(nftables.TableFamily(42))
		want := "unknown(42)"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestTableFlagMaskString(t *testing.T) {
	t.Run("single", func(t *testing.T) {
		got := tableFlagMaskString(unix.NFT_TABLE_F_DORMANT)
		want := "dormant"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("none", func(t *testing.T) {
		got := tableFlagMaskString(0)
		want := ""
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestTableFlagString(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		got := tableFlagString(1 << 20)
		want := "unknown(20)"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("none", func(t *testing.T) {
		got := tableFlagString(0)
		want := "none"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestHookString(t *testing.T) {
	t.Run("input", func(t *testing.T) {
		got := hookString(nftables.TableFamilyINet, nftables.ChainHookInput)
		want := "input"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("unknownINet", func(t *testing.T) {
		got := hookString(nftables.TableFamilyINet, nftables.ChainHook(42))
		want := "unknown(42)"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("unknownFamily", func(t *testing.T) {
		got := hookString(nftables.TableFamily(42), nftables.ChainHook(42))
		want := "unknown(42)"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}
