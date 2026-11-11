package device

import (
	"runtime"
	"testing"
	"time"
)

// TestReleaseWakesAParkedWriter pins the invariant B7 violated: when the
// outbound backlog drops below the cap, a writer parked in waitOutboundSpace
// must be woken. Before releaseOutboundPackets existed the only wake came from
// Peer.Stop, so a drained pipeline left its writer asleep forever.
func TestReleaseWakesAParkedWriter(t *testing.T) {
	var peer Peer
	peer.isRunning.Store(true)
	peer.queuedOutboundPackets.Store(maxQueuedOutboundPackets)

	done := make(chan bool, 1)
	go func() {
		done <- peer.waitOutboundSpace()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		peer.outboundSpace.Lock()
		parked := peer.outboundSpace.ready != nil
		peer.outboundSpace.Unlock()
		if parked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the writer never parked: the wake channel was not created")
		}
		runtime.Gosched()
	}

	peer.releaseOutboundPackets(1)

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("waitOutboundSpace reported a stopped peer while it was running")
		}
		if remaining := peer.queuedOutboundPackets.Load(); remaining != maxQueuedOutboundPackets-1 {
			t.Fatalf("queuedOutboundPackets = %d after one release, want %d", remaining, maxQueuedOutboundPackets-1)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("releaseOutboundPackets did not wake the parked writer")
	}
}

// TestReleaseAboveTheCapKeepsTheWriterParked is the negative control: freeing a
// slot while the backlog is still over the cap must not let a new packet in.
func TestReleaseAboveTheCapKeepsTheWriterParked(t *testing.T) {
	var peer Peer
	peer.isRunning.Store(true)
	peer.queuedOutboundPackets.Store(maxQueuedOutboundPackets + 4)

	done := make(chan bool, 1)
	go func() {
		done <- peer.waitOutboundSpace()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		peer.outboundSpace.Lock()
		parked := peer.outboundSpace.ready != nil
		peer.outboundSpace.Unlock()
		if parked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the writer never parked")
		}
		runtime.Gosched()
	}

	peer.releaseOutboundPackets(1)
	select {
	case <-done:
		t.Fatal("the writer was released while the backlog was still at or above the cap")
	case <-time.After(100 * time.Millisecond):
	}

	// Free the remaining excess; now it must wake.
	peer.releaseOutboundPackets(4)
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("waitOutboundSpace reported a stopped peer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the writer was not woken after the backlog fell below the cap")
	}
}

// TestStopStillWakesAParkedWriter keeps the shutdown path pinned.
func TestStopStillWakesAParkedWriter(t *testing.T) {
	var peer Peer
	peer.isRunning.Store(true)
	peer.queuedOutboundPackets.Store(maxQueuedOutboundPackets)

	done := make(chan bool, 1)
	go func() {
		done <- peer.waitOutboundSpace()
	}()
	time.Sleep(20 * time.Millisecond)

	peer.isRunning.Store(false)
	peer.wakeOutboundWaiters()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("waitOutboundSpace returned true for a stopped peer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stopping the peer did not wake the parked writer")
	}
}
