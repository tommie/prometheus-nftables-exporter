package main

import (
	"fmt"
	"log"
	"strconv"

	"github.com/google/nftables"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	collectionFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "nftables",
		Name:      "collection_failures",
		Help:      "Collection failures while reading from nftables.",
	})

	ineligibleRules = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "nftables",
		Name:      "ineligible_rules",
		Help:      "Number of rules that were not exported for some reason.",
	}, []string{"family", "table", "reason"})

	ineligibleCounters = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "nftables",
		Name:      "ineligible_counters",
		Help:      "Number of counters that were not exported for some reason.",
	}, []string{"family", "table", "reason"})

	ineligibleSets = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "nftables",
		Name:      "ineligible_sets",
		Help:      "Number of sets that were not exported for some reason.",
	}, []string{"family", "table", "reason"})
)

func init() {
	prometheus.MustRegister(collectionFailures)
	prometheus.MustRegister(ineligibleRules)
}

// An nftCollector uses an NFTables connection to export some metadata
// and statistics about Netfilters.
type nftCollector struct {
	conn              nftConn
	ruleCommentFilter func(string) bool
	counterNameFilter func(string) bool
	setNameFilter     func(string) bool

	// Metadata

	tableDesc *prometheus.Desc
	chainDesc *prometheus.Desc
	setDesc   *prometheus.Desc

	// Statistics

	chainRuleCountDesc    *prometheus.Desc
	rulePacketCounterDesc *prometheus.Desc
	ruleByteCounterDesc   *prometheus.Desc
	packetCounterDesc     *prometheus.Desc
	byteCounterDesc       *prometheus.Desc
	setSizeDesc           *prometheus.Desc
}

// nftConn is implemented by *nftables.Conn.
type nftConn interface {
	ListTables() ([]*nftables.Table, error)
	ListChains() ([]*nftables.Chain, error)
	GetObjects(*nftables.Table) ([]nftables.Obj, error)
	GetRule(*nftables.Table, *nftables.Chain) ([]*nftables.Rule, error)
	GetSets(*nftables.Table) ([]*nftables.Set, error)
	GetSetElements(*nftables.Set) ([]nftables.SetElement, error)
}

// newNFTCollector creates a new collector. Objects are exported if
// the filter returns true.
func newNFTCollector(conn nftConn, ruleCommentFilter, counterNameFilter, setNameFilter func(string) bool) *nftCollector {
	return &nftCollector{
		conn:              conn,
		ruleCommentFilter: ruleCommentFilter,
		counterNameFilter: counterNameFilter,
		setNameFilter:     setNameFilter,

		tableDesc: prometheus.NewDesc("nftables_table_metadata", "Metadata about each table. Value is always 1.", []string{"family", "table" /* values: */, "flags"}, nil),
		chainDesc: prometheus.NewDesc("nftables_chain_metadata", "Metadata about each chain. Value is always 1.", []string{"family", "table", "chain" /* values: */, "hook", "policy", "priority"}, nil),
		setDesc:   prometheus.NewDesc("nftables_set_metadata", "Metadata about each set. Value is always 1.", []string{"family", "table", "set" /* values: */, "ismap", "keytype", "datatype"}, nil),

		chainRuleCountDesc:    prometheus.NewDesc("nftables_chain_rule_count", "Total rule count in chain.", []string{"family", "table", "chain"}, nil),
		rulePacketCounterDesc: prometheus.NewDesc("nftables_rule_packet_count", "Number of packets matching the rule.", []string{"family", "table", "chain", "comment"}, nil),
		ruleByteCounterDesc:   prometheus.NewDesc("nftables_rule_byte_count", "Number of bytes matching the rule.", []string{"family", "table", "chain", "comment"}, nil),
		packetCounterDesc:     prometheus.NewDesc("nftables_counter_packet_count", "Number of packets triggering the counter.", []string{"family", "table", "counter"}, nil),
		byteCounterDesc:       prometheus.NewDesc("nftables_counter_byte_count", "Number of bytes triggering the counter.", []string{"family", "table", "counter"}, nil),
		setSizeDesc:           prometheus.NewDesc("nftables_set_size", "Number of elements in the set.", []string{"family", "table", "set"}, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *nftCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tableDesc
	ch <- c.chainDesc
	ch <- c.setDesc
	ch <- c.chainRuleCountDesc
	ch <- c.rulePacketCounterDesc
	ch <- c.ruleByteCounterDesc
	ch <- c.packetCounterDesc
	ch <- c.byteCounterDesc
	ch <- c.setSizeDesc
}

// Collector implements prometheus.Collector.
func (c *nftCollector) Collect(ch chan<- prometheus.Metric) {
	ts, err := c.conn.ListTables()
	if err != nil {
		log.Printf("Failed to list NF tables: %v", err)
		collectionFailures.Inc()
		return
	}

	for _, t := range ts {
		if err := c.collectTable(ch, t); err != nil {
			log.Printf("%v (ignored)", err)
			collectionFailures.Inc()
		}
	}

	cns, err := c.conn.ListChains()
	if err != nil {
		log.Printf("Failed to list NF chains: %v", err)
		collectionFailures.Inc()
		return
	}

	for _, cn := range cns {
		if err := c.collectChain(ch, cn); err != nil {
			log.Printf("%v (ignored)", err)
			collectionFailures.Inc()
		}
	}
}

// collectTable exports metrics about a single table.
func (c *nftCollector) collectTable(ch chan<- prometheus.Metric, t *nftables.Table) error {
	ch <- prometheus.MustNewConstMetric(c.tableDesc, prometheus.GaugeValue, 1, tableFamilyString(t.Family), t.Name, tableFlagMaskString(t.Flags))

	os, err := c.conn.GetObjects(t)
	if err != nil {
		collectionFailures.Inc()
		return fmt.Errorf("listing objects for table %q: %v", t.Name, err)
	}

	fam := tableFamilyString(t.Family)
	for _, o := range os {
		if cnt, ok := o.(*nftables.CounterObj); ok {
			if !c.counterNameFilter(cnt.Name) {
				ineligibleCounters.WithLabelValues(fam, t.Name, "comment-filter").Inc()
				continue
			}

			ch <- prometheus.MustNewConstMetric(c.packetCounterDesc, prometheus.CounterValue, float64(cnt.Packets), fam, t.Name, cnt.Name)
			ch <- prometheus.MustNewConstMetric(c.byteCounterDesc, prometheus.CounterValue, float64(cnt.Bytes), fam, t.Name, cnt.Name)
		}
	}

	sts, err := c.conn.GetSets(t)
	if err != nil {
		collectionFailures.Inc()
		return fmt.Errorf("listing sets for table %q: %v", t.Name, err)
	}

	for _, st := range sts {
		if err := c.collectSet(ch, fam, t, st); err != nil {
			log.Printf("%v (ignored)", err)
			collectionFailures.Inc()
		}
	}

	return nil
}

// collectChain exports metrics about a single chain.
func (c *nftCollector) collectChain(ch chan<- prometheus.Metric, cn *nftables.Chain) error {
	ch <- prometheus.MustNewConstMetric(c.chainDesc, prometheus.GaugeValue, 1, tableFamilyString(cn.Table.Family), cn.Table.Name, cn.Name, hookString(cn.Table.Family, cn.Hooknum), chainPolicyString(cn.Policy), strconv.FormatInt(int64(cn.Priority), 10))

	rs, err := c.conn.GetRule(cn.Table, cn)
	if err != nil {
		return fmt.Errorf("listing rules of chain %s:%s: %v", cn.Table.Name, cn.Name, err)
	}

	fam := tableFamilyString(cn.Table.Family)
	ch <- prometheus.MustNewConstMetric(c.chainRuleCountDesc, prometheus.GaugeValue, float64(len(rs)), fam, cn.Table.Name, cn.Name)

	for _, r := range rs {
		if err := c.collectRule(ch, fam, r); err != nil {
			log.Printf("%v (ignored)", err)
			collectionFailures.Inc()
		}
	}

	return nil
}

// collectRule exports metrics about a single rule.
func (c *nftCollector) collectRule(ch chan<- prometheus.Metric, family string, r *nftables.Rule) error {
	cmnt, err := ruleComment(r)
	if err != nil {
		ineligibleRules.WithLabelValues(family, r.Table.Name, "comment-error").Inc()
		return fmt.Errorf("extracting rule comment: %v", err)
	}
	if cmnt == "" {
		ineligibleRules.WithLabelValues(family, r.Table.Name, "no-comment").Inc()
		return nil
	}
	if !c.ruleCommentFilter(cmnt) {
		ineligibleRules.WithLabelValues(family, r.Table.Name, "comment-filter").Inc()
		return nil
	}

	cnt := ruleCounter(r)
	if cnt == nil {
		ineligibleRules.WithLabelValues(family, r.Table.Name, "no-counter").Inc()
		return nil
	}

	ch <- prometheus.MustNewConstMetric(c.rulePacketCounterDesc, prometheus.CounterValue, float64(cnt.Packets), family, r.Table.Name, r.Chain.Name, cmnt)
	ch <- prometheus.MustNewConstMetric(c.ruleByteCounterDesc, prometheus.CounterValue, float64(cnt.Bytes), family, r.Table.Name, r.Chain.Name, cmnt)

	return nil
}

// collectSet exports metrics about a single set/map.
func (c *nftCollector) collectSet(ch chan<- prometheus.Metric, family string, t *nftables.Table, st *nftables.Set) error {
	if !c.setNameFilter(st.Name) {
		ineligibleSets.WithLabelValues(family, t.Name, "name-filter").Inc()
		return nil
	}

	isMap := "0"
	if st.IsMap {
		isMap = "1"
	}
	ch <- prometheus.MustNewConstMetric(c.setDesc, prometheus.GaugeValue, 1, family, t.Name, st.Name, isMap, st.KeyType.Name, st.DataType.Name)

	els, err := c.conn.GetSetElements(st)
	if err != nil {
		ineligibleSets.WithLabelValues(family, t.Name, "elements-error").Inc()
		return fmt.Errorf("getting elements for set %s/%s/%s: %v", family, t.Name, st.Name, err)
	}

	ch <- prometheus.MustNewConstMetric(c.setSizeDesc, prometheus.GaugeValue, float64(len(els)), family, t.Name, st.Name)

	return nil
}
