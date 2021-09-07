package main

import (
	"fmt"
	"math/bits"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/tommie/prometheus-nftables-exporter/udata"
	"golang.org/x/sys/unix"
)

// ruleCounter extracts the counter and returns it, or nil.
func ruleCounter(r *nftables.Rule) *expr.Counter {
	for _, e := range r.Exprs {
		if cnt, ok := e.(*expr.Counter); ok {
			return cnt
		}
	}
	return nil
}

// ruleComment extracts the comment and returns it, or the empty
// string if there was no comment.
func ruleComment(r *nftables.Rule) (string, error) {
	as, err := udata.Unmarshal(r.UserData, udata.UnmarshalRuleAttr)
	if err != nil {
		return "", err
	}
	for _, a := range as {
		if c, ok := a.(udata.Comment); ok {
			return string(c), nil
		}
	}
	return "", nil
}

// chainPolicyString returns a string representation of a
// ChainPolicy. If the input is nil, this defaults to "accept", like
// Netfilter does.
func chainPolicyString(p *nftables.ChainPolicy) string {
	if p == nil {
		return "accept"
	}
	switch *p {
	case nftables.ChainPolicyDrop:
		return "drop"
	case nftables.ChainPolicyAccept:
		return "accept"
	default:
		return fmt.Sprintf("unknown(%d)", *p)
	}
}

// tableFamilyString returns a string representation of a TableFamily.
func tableFamilyString(tf nftables.TableFamily) string {
	switch tf {
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyNetdev:
		return "netdev"
	case nftables.TableFamilyBridge:
		return "bridge"
	default:
		return fmt.Sprintf("unknown(%d)", tf)
	}
}

// tableFlagMaskString returns a comma-separated list of table flags.
func tableFlagMaskString(v uint32) string {
	var fs []string
	for m := uint32(1); m <= maxTableFlag; m <<= 1 {
		if v&m != 0 {
			fs = append(fs, tableFlagString(m))
		}
	}
	return strings.Join(fs, ",")
}

const maxTableFlag = unix.NFT_TABLE_F_DORMANT

// tableFlagString returns a string representation of a table flag.
func tableFlagString(v uint32) string {
	switch v {
	case 0:
		return "none"
	case unix.NFT_TABLE_F_DORMANT:
		return "dormant"
	default:
		return fmt.Sprintf("unknown(%d)", bits.TrailingZeros32(v))
	}
}

// hookString returns a string representation of a ChainHook. The
// interpretation of the hook value depends on the family.
func hookString(tf nftables.TableFamily, v nftables.ChainHook) string {
	switch tf {
	case nftables.TableFamilyINet, nftables.TableFamilyIPv4, nftables.TableFamilyIPv6:
		switch v {
		case nftables.ChainHookPrerouting:
			return "prerouting"
		case nftables.ChainHookInput:
			return "input"
		case nftables.ChainHookForward:
			return "forward"
		case nftables.ChainHookOutput:
			return "output"
		case nftables.ChainHookPostrouting:
			return "postrouting"
		}
	case nftables.TableFamilyNetdev:
		switch v {
		case nftables.ChainHookIngress:
			return "ingress"
		}
	}
	return fmt.Sprintf("unknown(%d)", v)
}
