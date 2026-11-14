//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// The GRO path writes a virtioNetHdr into the headroom of every buffer it returns to the TUN
// file descriptor. An item removed from the coalescing table is never revisited by
// applyTCPCoalesceAccounting, and a packet that is not a GRO candidate never becomes an item at
// all, so both paths have to clear the headroom themselves - otherwise a stale or garbage header
// reaches the kernel. The device tests cannot see this: the function only runs when a Linux TUN
// negotiates GRO.

const (
	groTestIPHeaderLen  = 20
	groTestTCPHeaderLen = 20
	groTestSegmentSize  = 100
)

var (
	groTestSource      = netip.MustParseAddrPort("192.0.2.1:1")
	groTestDestination = netip.MustParseAddrPort("192.0.2.2:1")
)

// tcp4GROPacket builds a syntactically valid IPv4/TCP packet with a virtio headroom, in the
// shape handleGRO reads: the packet starts at virtioNetHdrLen and fills the whole slice.
func tcp4GROPacket(source, destination netip.AddrPort, seq uint32, segmentSize int) []byte {
	totalLen := groTestIPHeaderLen + groTestTCPHeaderLen + segmentSize
	// The capacity is what lets coalescing append in place: a buffer with no growing room is an
	// "insufficient capacity" result, not the invalid-checksum one this fixture is about.
	packet := make([]byte, virtioNetHdrLen+totalLen, 65535)
	ipHeader := packet[virtioNetHdrLen:]
	ipHeader[0] = 0x45 // IPv4, 5 words of header
	binary.BigEndian.PutUint16(ipHeader[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHeader[4:], 1) // identification
	ipHeader[8] = 64                            // TTL
	ipHeader[9] = unix.IPPROTO_TCP
	source4 := source.Addr().As4()
	destination4 := destination.Addr().As4()
	copy(ipHeader[12:16], source4[:])
	copy(ipHeader[16:20], destination4[:])
	binary.BigEndian.PutUint16(ipHeader[10:], 0)
	binary.BigEndian.PutUint16(ipHeader[10:], ^checksum(ipHeader[:groTestIPHeaderLen], 0))

	tcpHeader := ipHeader[groTestIPHeaderLen:]
	binary.BigEndian.PutUint16(tcpHeader[0:], source.Port())
	binary.BigEndian.PutUint16(tcpHeader[2:], destination.Port())
	binary.BigEndian.PutUint32(tcpHeader[4:], seq)
	binary.BigEndian.PutUint32(tcpHeader[8:], 1) // acknowledgement number
	tcpHeader[12] = 5 << 4                       // data offset
	tcpHeader[13] = tcpFlagACK
	binary.BigEndian.PutUint16(tcpHeader[14:], 3000) // window
	binary.BigEndian.PutUint16(tcpHeader[16:], 0)
	for i := 0; i < segmentSize; i++ {
		tcpHeader[groTestTCPHeaderLen+i] = byte(i)
	}
	pseudoHeader := pseudoHeaderChecksumNoFold(unix.IPPROTO_TCP, ipHeader[12:16], ipHeader[16:20], uint16(groTestTCPHeaderLen+segmentSize))
	binary.BigEndian.PutUint16(tcpHeader[16:], ^checksum(tcpHeader, pseudoHeader))
	return packet
}

// poisonVirtioHeader fills the headroom with a recognisable pattern, the way a buffer that came
// back from an earlier GRO cycle carries one, and fails if the pattern did not land there.
func poisonVirtioHeader(t *testing.T, packet []byte) {
	t.Helper()
	poison := bytes.Repeat([]byte{0xAB}, virtioNetHdrLen)
	copy(packet[:virtioNetHdrLen], poison)
	if !bytes.Equal(packet[:virtioNetHdrLen], poison) {
		t.Fatal("the test failed to poison the virtio header, so the clear below would prove nothing")
	}
}

func requireClearedVirtioHeader(t *testing.T, packet []byte) {
	t.Helper()
	zero := make([]byte, virtioNetHdrLen)
	if !bytes.Equal(packet[:virtioNetHdrLen], zero) {
		t.Fatalf("the virtio header still carries %x after GRO, so the packet would be written to the TUN fd with a stale header", packet[:virtioNetHdrLen])
	}
}

// The item dropped from the table because its checksum is invalid is still written back: it was
// appended to toWrite when it was inserted, and the delete happens on the next packet. Before the
// clear, that write carried the header bytes the buffer happened to have.
func TestHandleGROClearsTheVirtioHeaderOfADroppedItem(t *testing.T) {
	first := tcp4GROPacket(groTestSource, groTestDestination, 1, groTestSegmentSize)
	// A wrong transport checksum is what makes the item invalid when the next segment meets it.
	first[virtioNetHdrLen+groTestIPHeaderLen+16] ^= 0xFF
	if checksumValid(first[virtioNetHdrLen:], groTestIPHeaderLen, unix.IPPROTO_TCP, false) {
		t.Fatal("the first packet must carry an invalid TCP checksum")
	}
	poisonVirtioHeader(t, first)

	second := tcp4GROPacket(groTestSource, groTestDestination, 1+groTestSegmentSize, groTestSegmentSize)
	third := tcp4GROPacket(groTestSource, groTestDestination, 1+2*groTestSegmentSize, groTestSegmentSize)
	if !checksumValid(second[virtioNetHdrLen:], groTestIPHeaderLen, unix.IPPROTO_TCP, false) {
		t.Fatal("the second packet must be valid, otherwise it is rejected instead of meeting the item")
	}

	buffers := [][]byte{first, second, third}
	toWrite := make([]int, 0, len(buffers))
	err := handleGRO(buffers, virtioNetHdrLen, newTCPGROTable(), newUDPGROTable(), 0, &toWrite)
	if err != nil {
		t.Fatalf("handleGRO failed: %s", err)
	}
	if len(toWrite) == 0 || toWrite[0] != 0 {
		t.Fatalf("the dropped item must still be written back first, toWrite is %v", toWrite)
	}
	requireClearedVirtioHeader(t, first)
}

// A packet that is not a GRO candidate is a passthrough: it is appended to toWrite untouched
// except for the header clear, which has to happen before it is written.
func TestHandleGROClearsTheVirtioHeaderOfAPassthroughPacket(t *testing.T) {
	packet := tcp4GROPacket(groTestSource, groTestDestination, 1, groTestSegmentSize)
	poisonVirtioHeader(t, packet)

	buffers := [][]byte{packet}
	toWrite := make([]int, 0, len(buffers))
	// TCP GRO disabled makes the packet a passthrough, which is the groResultNoop path.
	err := handleGRO(buffers, virtioNetHdrLen, newTCPGROTable(), newUDPGROTable(), tcpGRODisabled, &toWrite)
	if err != nil {
		t.Fatalf("handleGRO failed: %s", err)
	}
	if len(toWrite) != 1 || toWrite[0] != 0 {
		t.Fatalf("the passthrough packet must be written back, toWrite is %v", toWrite)
	}
	requireClearedVirtioHeader(t, packet)
}
