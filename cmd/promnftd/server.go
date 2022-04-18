package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// startCollectorServer reads global flags and starts the HTTP
// server. Callers should run the returned cleanup function once the
// server is stopped.
func startCollectorServer(ctx context.Context, conn nftConn, ruleCommentFilter, counterNameFilter, setNameFilter, httpAddr string, log *log.Logger) (net.Listener, *http.Server, func(), error) {
	rcre, err := regexp.Compile("^(" + ruleCommentFilter + ")$")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid -rule-comments: %v", err)
	}
	cnre, err := regexp.Compile("^(" + counterNameFilter + ")$")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid -counter-names: %v", err)
	}
	stre, err := regexp.Compile("^(" + setNameFilter + ")$")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid -set-names: %v", err)
	}

	nftColl := newNFTCollector(conn, rcre.MatchString, cnre.MatchString, stre.MatchString)
	if err := prometheus.Register(nftColl); err != nil {
		return nil, nil, nil, err
	}

	http.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		ErrorLog: log,
	}))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/metrics", http.StatusFound)
	})

	l, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return nil, nil, nil, err
	}

	s := &http.Server{Addr: l.Addr().String()}

	cctx, cancel := context.WithCancel(ctx)
	stopHTTPServerOnSignal(cctx, s, os.Interrupt, syscall.SIGTERM)

	return l, s, func() {
		cancel()
		prometheus.Unregister(nftColl)
	}, nil
}

// stopHTTPServerOnSignal listens for OS signals, and returns. On
// signal, it runs s.Shutdown. If another signal is raised, s.Close is
// called. Honors context cancellation.
func stopHTTPServerOnSignal(ctx context.Context, s shutdownerCloser, sigs ...os.Signal) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sigs...)

	go func() {
		defer close(ch)
		defer signal.Stop(ch)

		select {
		case <-ch:
			// continue
		case <-ctx.Done():
			return
		}
		if err := s.Shutdown(ctx); err != nil {
			log.Printf("Shutdown failed: %v", err)
		}

		select {
		case <-ch:
			// continue
		case <-ctx.Done():
			return
		}
		if err := s.Close(); err != nil {
			log.Printf("Close failed: %v", err)
		}
	}()
}

type shutdownerCloser interface {
	Shutdown(context.Context) error
	Close() error
}
