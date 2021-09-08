package main

import (
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"
)

func TestNFTCollector(t *testing.T) {
	drop := nftables.ChainPolicyDrop
	conn := fakeNFTConn{
		tables: []*nftables.Table{
			{Name: "table1", Family: nftables.TableFamilyINet},
			{Name: "table2", Family: nftables.TableFamilyINet, Flags: unix.NFT_TABLE_F_DORMANT},
		},
		chains: []*nftables.Chain{
			{Name: "chain1", Table: &nftables.Table{Name: "table1", Family: nftables.TableFamilyINet}},
			{Name: "chain2", Table: &nftables.Table{Name: "table1", Family: nftables.TableFamilyINet}, Hooknum: nftables.ChainHookInput, Priority: 42, Policy: &drop},
		},
		objs: map[string][]nftables.Obj{
			"table1": []nftables.Obj{
				&nftables.CounterObj{Name: "counter1", Packets: 42, Bytes: 4711},
			},
		},
		rules: map[string][]*nftables.Rule{
			"table1/chain1": []*nftables.Rule{
				{Table: &nftables.Table{Name: "table1", Family: nftables.TableFamilyINet}, Chain: &nftables.Chain{Name: "chain1"}},
				{Table: &nftables.Table{Name: "table1", Family: nftables.TableFamilyINet}, Chain: &nftables.Chain{Name: "chain1"},
					Exprs:    []expr.Any{&expr.Counter{Packets: 4, Bytes: 2}},
					UserData: makeRuleComment("test comment")},
			},
		},
		sets: map[string][]*nftables.Set{
			"table1": {
				&nftables.Set{Name: "set1", IsMap: false, KeyType: nftables.SetDatatype{Name: "ipv4_addr"}},
				&nftables.Set{Name: "map1", IsMap: true, KeyType: nftables.SetDatatype{Name: "ipv4_addr"}, DataType: nftables.SetDatatype{Name: "string"}},
			},
		},
		setEls: map[string][]nftables.SetElement{
			"set1": {
				nftables.SetElement{},
				nftables.SetElement{},
			},
		},
	}
	c := newNFTCollector(&conn, allFilter, allFilter, allFilter)
	want := `
# HELP nftables_chain_metadata Metadata about each chain. Value is always 1.
# TYPE nftables_chain_metadata gauge
nftables_chain_metadata{chain="chain1",family="inet",hook="prerouting",policy="accept",priority="0",table="table1"} 1
nftables_chain_metadata{chain="chain2",family="inet",hook="input",policy="drop",priority="42",table="table1"} 1

# HELP nftables_set_metadata Metadata about each set. Value is always 1.
# TYPE nftables_set_metadata gauge
nftables_set_metadata{datatype="",family="inet",ismap="0",keytype="ipv4_addr",set="set1",table="table1"} 1
nftables_set_metadata{datatype="string",family="inet",ismap="1",keytype="ipv4_addr",set="map1",table="table1"} 1

# HELP nftables_table_metadata Metadata about each table. Value is always 1.
# TYPE nftables_table_metadata gauge
nftables_table_metadata{family="inet",flags="",table="table1"} 1
nftables_table_metadata{family="inet",flags="dormant",table="table2"} 1

# HELP nftables_chain_rule_count Total rule count in chain.
# TYPE nftables_chain_rule_count gauge
nftables_chain_rule_count{chain="chain1",family="inet",table="table1"} 2
nftables_chain_rule_count{chain="chain2",family="inet",table="table1"} 0

# HELP nftables_rule_byte_count Number of bytes matching the rule.
# TYPE nftables_rule_byte_count counter
nftables_rule_byte_count{chain="chain1",comment="test comment",family="inet",table="table1"} 2
# HELP nftables_rule_packet_count Number of packets matching the rule.
# TYPE nftables_rule_packet_count counter
nftables_rule_packet_count{chain="chain1",comment="test comment",family="inet",table="table1"} 4

# HELP nftables_counter_byte_count Number of bytes triggering the counter.
# TYPE nftables_counter_byte_count counter
nftables_counter_byte_count{counter="counter1",family="inet",table="table1"} 4711
# HELP nftables_counter_packet_count Number of packets triggering the counter.
# TYPE nftables_counter_packet_count counter
nftables_counter_packet_count{counter="counter1",family="inet",table="table1"} 42

# HELP nftables_set_size Number of elements in the set.
# TYPE nftables_set_size gauge
nftables_set_size{family="inet",set="map1",table="table1"} 0
nftables_set_size{family="inet",set="set1",table="table1"} 2
`

	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"nftables_table_metadata",
		"nftables_chain_metadata",
		"nftables_set_metadata",
		"nftables_chain_rule_count",
		"nftables_rule_packet_count",
		"nftables_rule_byte_count",
		"nftables_counter_packet_count",
		"nftables_counter_byte_count",
		"nftables_set_size"); err != nil {
		t.Errorf("CollectAndCompare: %v", err)
	}
}

func allFilter(string) bool { return true }

func TestNFTCollectorRuleCommentFilter(t *testing.T) {
	conn := fakeNFTConn{
		chains: []*nftables.Chain{
			{Name: "chain1", Table: &nftables.Table{Name: "table1", Family: nftables.TableFamilyINet}},
		},
		rules: map[string][]*nftables.Rule{
			"table1/chain1": []*nftables.Rule{
				{Table: &nftables.Table{Name: "table1", Family: nftables.TableFamilyINet}, Chain: &nftables.Chain{Name: "chain1"},
					Exprs:    []expr.Any{&expr.Counter{Packets: 4, Bytes: 2}},
					UserData: makeRuleComment("match")},
				{Table: &nftables.Table{Name: "table1", Family: nftables.TableFamilyINet}, Chain: &nftables.Chain{Name: "chain1"},
					Exprs:    []expr.Any{&expr.Counter{Packets: 42, Bytes: 4711}},
					UserData: makeRuleComment("nomatch")},
			},
		},
	}
	c := newNFTCollector(&conn, func(s string) bool { return s == "match" }, allFilter, allFilter)
	want := `
# HELP nftables_rule_byte_count Number of bytes matching the rule.
# TYPE nftables_rule_byte_count counter
nftables_rule_byte_count{chain="chain1",comment="match",family="inet",table="table1"} 2
# HELP nftables_rule_packet_count Number of packets matching the rule.
# TYPE nftables_rule_packet_count counter
nftables_rule_packet_count{chain="chain1",comment="match",family="inet",table="table1"} 4
`

	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "nftables_rule_packet_count", "nftables_rule_byte_count"); err != nil {
		t.Errorf("CollectAndCompare: %v", err)
	}
}

func TestNFTCollectorCounterNameFilter(t *testing.T) {
	conn := fakeNFTConn{
		tables: []*nftables.Table{
			{Name: "table1", Family: nftables.TableFamilyINet},
		},
		objs: map[string][]nftables.Obj{
			"table1": []nftables.Obj{
				&nftables.CounterObj{Name: "nomatch", Packets: 4, Bytes: 2},
				&nftables.CounterObj{Name: "match", Packets: 42, Bytes: 4711},
			},
		},
	}
	c := newNFTCollector(&conn, allFilter, func(s string) bool { return s == "match" }, allFilter)
	want := `
# HELP nftables_counter_byte_count Number of bytes triggering the counter.
# TYPE nftables_counter_byte_count counter
nftables_counter_byte_count{counter="match",family="inet",table="table1"} 4711
# HELP nftables_counter_packet_count Number of packets triggering the counter.
# TYPE nftables_counter_packet_count counter
nftables_counter_packet_count{counter="match",family="inet",table="table1"} 42
`

	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "nftables_counter_packet_count", "nftables_counter_byte_count"); err != nil {
		t.Errorf("CollectAndCompare: %v", err)
	}
}

func TestNFTCollectorSetNameFilter(t *testing.T) {
	conn := fakeNFTConn{
		tables: []*nftables.Table{
			{Name: "table1", Family: nftables.TableFamilyINet},
		},
		sets: map[string][]*nftables.Set{
			"table1": {
				&nftables.Set{Name: "nomatch", IsMap: false, KeyType: nftables.SetDatatype{Name: "ipv4_addr"}},
				&nftables.Set{Name: "match", IsMap: true, KeyType: nftables.SetDatatype{Name: "ipv4_addr"}, DataType: nftables.SetDatatype{Name: "string"}},
			},
		},
	}
	c := newNFTCollector(&conn, allFilter, allFilter, func(s string) bool { return s == "match" })
	want := `
# HELP nftables_set_metadata Metadata about each set. Value is always 1.
# TYPE nftables_set_metadata gauge
nftables_set_metadata{datatype="string",family="inet",ismap="1",keytype="ipv4_addr",set="match",table="table1"} 1
# HELP nftables_set_size Number of elements in the set.
# TYPE nftables_set_size gauge
nftables_set_size{family="inet",set="match",table="table1"} 0
`

	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "nftables_set_metadata", "nftables_set_size"); err != nil {
		t.Errorf("CollectAndCompare: %v", err)
	}
}

var _ nftConn = &nftables.Conn{}

type fakeNFTConn struct {
	tables []*nftables.Table
	chains []*nftables.Chain
	objs   map[string][]nftables.Obj        // Key is "table".
	rules  map[string][]*nftables.Rule      // Key is "table/chain".
	sets   map[string][]*nftables.Set       // Key is "table".
	setEls map[string][]nftables.SetElement // Key is "set".
}

func (c *fakeNFTConn) ListTables() ([]*nftables.Table, error) {
	return c.tables, nil
}

func (c *fakeNFTConn) ListChains() ([]*nftables.Chain, error) {
	return c.chains, nil
}

func (c *fakeNFTConn) GetObjects(t *nftables.Table) ([]nftables.Obj, error) {
	return c.objs[t.Name], nil
}

func (c *fakeNFTConn) GetRule(t *nftables.Table, cn *nftables.Chain) ([]*nftables.Rule, error) {
	return c.rules[t.Name+"/"+cn.Name], nil
}

func (c *fakeNFTConn) GetSets(t *nftables.Table) ([]*nftables.Set, error) {
	return c.sets[t.Name], nil
}

func (c *fakeNFTConn) GetSetElements(st *nftables.Set) ([]nftables.SetElement, error) {
	return c.setEls[st.Name], nil
}
