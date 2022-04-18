// Command promnftd is a Netfilter Tables metrics exporter for Prometheus.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/nftables"
)

var (
	ruleCommentFilter = flag.String("rule-comments", ".*", "Regular expression of comments of rules to include (fully anchored).")
	counterNameFilter = flag.String("counter-names", ".*", "Regular expression of names of counters to include (fully anchored).")
	setNameFilter     = flag.String("set-names", ".*", "Regular expression of names of sets to include (fully anchored).")

	httpAddr         = flag.String("http-addr", "localhost:0", "TCP-address to listen for HTTP connections on.")
	standaloneStderr = flag.Bool("standalone-log", false, "Log to stderr, with time prefix.")
)

func main() {
	flag.Parse()

	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

// run starts everything and waits for a signal to terminate.
func run(ctx context.Context) error {
	ll := log.New(os.Stderr, "", log.LstdFlags)
	if !*standaloneStderr {
		log.SetFlags(0)
		log.SetOutput(os.Stdout)
		ll = log.New(os.Stdout, "", 0)
	}

	var conn nftables.Conn
	if _, err := conn.ListTables(); err != nil {
		return fmt.Errorf("unable to access NF tables: %v", err)
	}

	l, s, cleanup, err := startCollectorServer(ctx, &conn, *ruleCommentFilter, *counterNameFilter, *setNameFilter, *httpAddr, ll)
	if err != nil {
		return err
	}
	defer cleanup()

	log.Printf("Listening for HTTP connections on %q...", s.Addr)
	if err := s.Serve(l); err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}
