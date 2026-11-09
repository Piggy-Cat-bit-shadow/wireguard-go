/* SPDX-License-Identifier: MIT
 *
 * NewPeerConfig.PresharedKey: the lazily created peer returned by a
 * PeerLookupFunc must carry the configured pre-shared key into its handshake
 * state, so a responder that only learns about a peer from the first
 * handshake initiation can still complete a PSK-protected handshake.
 */

package device

import (
	"context"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testPresharedKey() NoisePresharedKey {
	var psk NoisePresharedKey
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	return psk
}

// A lazy peer created through PeerLookupFunc must apply NewPeerConfig's
// PresharedKey, both in the handshake state and in the uapi view.
func TestNewPeerConfigPresharedKeyLazyPeer(t *testing.T) {
	dev := NewDevice(context.Background(), newChanTun(), newChanBind(), NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	psk := testPresharedKey()
	var pkB NoisePublicKey
	for i := range pkB {
		pkB[i] = byte(0xa0 + i)
	}

	dev.SetPeerLookupFunc(func(pk NoisePublicKey) (*NewPeerConfig, bool) {
		if pk != pkB {
			return nil, false
		}
		return &NewPeerConfig{
			AllowedIPs:   []netip.Prefix{netip.PrefixFrom(testIPB, 32)},
			PresharedKey: psk,
		}, true
	})

	peer := dev.LookupPeer(pkB)
	if peer == nil {
		t.Fatal("LookupPeer did not create the configured peer")
	}
	if peer.handshake.presharedKey != psk {
		t.Fatalf("lazy peer handshake preshared key = %x, want %x", peer.handshake.presharedKey[:], psk[:])
	}

	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	want := "preshared_key=" + hex.EncodeToString(psk[:]) + "\n"
	if !strings.Contains(got, want) {
		t.Fatalf("IpcGet does not report the lazy peer's preshared key:\n%s", got)
	}
}

// A zero NewPeerConfig.PresharedKey must leave the PSK layer disabled.
func TestNewPeerConfigZeroPresharedKeyLazyPeer(t *testing.T) {
	dev := NewDevice(context.Background(), newChanTun(), newChanBind(), NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	var pkB NoisePublicKey
	for i := range pkB {
		pkB[i] = byte(0xb0 + i)
	}
	dev.SetPeerLookupFunc(func(pk NoisePublicKey) (*NewPeerConfig, bool) {
		if pk != pkB {
			return nil, false
		}
		return &NewPeerConfig{AllowedIPs: []netip.Prefix{netip.PrefixFrom(testIPB, 32)}}, true
	})

	peer := dev.LookupPeer(pkB)
	if peer == nil {
		t.Fatal("LookupPeer did not create the configured peer")
	}
	if peer.handshake.presharedKey != (NoisePresharedKey{}) {
		t.Fatalf("lazy peer handshake preshared key = %x, want zero", peer.handshake.presharedKey[:])
	}
}

// newLazyPSKResponder brings up a responder whose only peer is created lazily
// from the incoming handshake, with the PSK supplied through NewPeerConfig,
// and an initiator with the PSK set through IpcSet.
func newLazyPSKResponder(t *testing.T, responderPSK, initiatorPSK NoisePresharedKey) (responder, initiator *Device, responderTun, initiatorTun *chanTun) {
	t.Helper()

	skA, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey A: %v", err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey B: %v", err)
	}
	pkA := skA.publicKey()
	pkB := skB.publicKey()

	bindA, bindB := newChanBindPair()
	responderTun = newChanTun()
	initiatorTun = newChanTun()

	responder = NewDevice(context.Background(), responderTun, bindA, NewLogger(LogLevelError, "responder: "), 1)
	t.Cleanup(responder.Close)
	initiator = NewDevice(context.Background(), initiatorTun, bindB, NewLogger(LogLevelError, "initiator: "), 1)
	t.Cleanup(initiator.Close)

	responder.SetPeerLookupFunc(func(pk NoisePublicKey) (*NewPeerConfig, bool) {
		if pk != pkB {
			return nil, false
		}
		return &NewPeerConfig{
			AllowedIPs:   []netip.Prefix{netip.PrefixFrom(testIPB, 32)},
			PresharedKey: responderPSK,
		}, true
	})

	if err := responder.IpcSet("private_key=" + hex.EncodeToString(skA[:]) + "\n"); err != nil {
		t.Fatalf("IpcSet responder: %v", err)
	}
	cfgB := "private_key=" + hex.EncodeToString(skB[:]) + "\n" +
		"replace_peers=true\npublic_key=" + hex.EncodeToString(pkA[:]) + "\n" +
		"endpoint=127.0.0.1:1\nallowed_ip=" + testIPA.String() + "/32\n"
	if initiatorPSK != (NoisePresharedKey{}) {
		cfgB += "preshared_key=" + hex.EncodeToString(initiatorPSK[:]) + "\n"
	}
	if err := initiator.IpcSet(cfgB); err != nil {
		t.Fatalf("IpcSet initiator: %v", err)
	}
	if err := responder.Up(); err != nil {
		t.Fatalf("Up responder: %v", err)
	}
	if err := initiator.Up(); err != nil {
		t.Fatalf("Up initiator: %v", err)
	}
	return responder, initiator, responderTun, initiatorTun
}

// With matching PSKs, a responder that only knows the peer through
// PeerLookupFunc must complete the handshake and deliver traffic.
func TestLazyPeerPresharedKeyHandshake(t *testing.T) {
	psk := testPresharedKey()
	_, _, responderTun, initiatorTun := newLazyPSKResponder(t, psk, psk)

	pkt := buildIPv4Packet(testIPB, testIPA, 16)
	send := func() { initiatorTun.toDevice <- append([]byte(nil), pkt...) }
	send()
	awaitPacket(t, responderTun, pkt, send)
}

// With mismatched PSKs, the same setup must not complete a handshake nor
// deliver traffic: the key really is consumed, not only stored.
func TestLazyPeerPresharedKeyMismatch(t *testing.T) {
	psk := testPresharedKey()
	other := psk
	other[0] ^= 0xff
	_, _, responderTun, initiatorTun := newLazyPSKResponder(t, psk, other)

	pkt := buildIPv4Packet(testIPB, testIPA, 16)
	initiatorTun.toDevice <- append([]byte(nil), pkt...)
	awaitNoPacket(t, responderTun, 3*time.Second)
}

func newChanBind() *chanBind {
	b, _ := newChanBindPair()
	return b
}
