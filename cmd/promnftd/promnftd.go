// Command promnftd is a Netfilter Tables metrics exporter for Prometheus.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/google/nftables"
)

var (
	httpAddr          = flag.String("http-addr", "localhost:0", "TCP-address to listen for HTTP connections on.")
	ruleCommentFilter = flag.String("rule-comments", ".*", "Regular expression of comments of rules to include (fully anchored).")
	counterNameFilter = flag.String("counter-names", ".*", "Regular expression of names of counters to include (fully anchored).")
	standaloneStderr  = flag.Bool("standalone-log", false, "Log to stderr, with time prefix.")
)

func main() {
	flag.Parse()

	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

// run starts everything and waits for a signal to terminate.
func run(ctx context.Context) error {
	if !*standaloneStderr {
		log.SetFlags(0)
		log.SetOutput(os.Stdout)
	}

	var conn nftables.Conn
	l, s, cleanup, err := startCollectorServer(ctx, &conn, *ruleCommentFilter, *counterNameFilter, *httpAddr)
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
