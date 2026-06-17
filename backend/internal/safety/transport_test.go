package safety

import (
	"context"
	"net"
	"testing"
)

func TestSafeDialContextBlocksPrivateIPBeforeDial(t *testing.T) {
	dialed := false
	dial := safeDialContext(func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, nil
	})

	if _, err := dial(context.Background(), "tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("expected private IP to be blocked")
	}
	if dialed {
		t.Fatal("private IP should be rejected before dialing")
	}
}
