package main

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/nftables"
	"sync"
)

func TestStartCollectorServer(t *testing.T) {
	ctx := context.Background()

	l, s, cleanup, err := startCollectorServer(ctx, &fakeNFTConn{
		tables: []*nftables.Table{
			{Name: "table1", Family: nftables.TableFamilyINet},
		},
	}, ".*", ".*", "localhost:0")
	if err != nil {
		t.Fatalf("startCollectorServer failed: %v", err)
	}
	defer cleanup()
	defer s.Close()

	go func() {
		if err := s.Serve(l); err != nil && err != http.ErrServerClosed {
			t.Fatalf("Serve failed: %v", err)
		}
	}()

	resp, err := http.Get("http://" + s.Addr + "/metrics")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer resp.Body.Close()

	got, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	want := `nftables_table_metadata{family="inet",flags="",table="table1"} 1`
	if !strings.Contains(string(got), want) {
		t.Errorf("Get: want %q, got:\n%s", want, string(got))
	}
}

func TestStopHTTPServerOnSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var s fakeShutdownerCloser
	s.shutdown.Add(1)
	s.close.Add(1)

	stopHTTPServerOnSignal(ctx, &s, os.Interrupt)

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess failed: %v", err)
	}

	if err := p.Signal(os.Interrupt); err != nil {
		t.Fatalf("Signal failed: %v", err)
	}
	s.shutdown.Wait()

	if err := p.Signal(os.Interrupt); err != nil {
		t.Fatalf("Signal failed: %v", err)
	}
	s.close.Wait()
}

var _ shutdownerCloser = &http.Server{}

type fakeShutdownerCloser struct {
	shutdown sync.WaitGroup
	close    sync.WaitGroup
}

func (sc *fakeShutdownerCloser) Shutdown(context.Context) error {
	sc.shutdown.Done()
	return nil
}

func (sc *fakeShutdownerCloser) Close() error {
	sc.close.Done()
	return nil
}
