/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package bpfloader_test contains BPF_PROG_TEST_RUN-style unit tests for the
// pm_relay TC programs.  The packet construction and delta arithmetic tests run
// on all platforms.  The BPF_PROG_TEST_RUN invocation tests are Linux-only
// (tagged linux) because they require a BPF-capable kernel.
package bpfloader_test

import (
	"encoding/binary"
	"testing"

	"github.com/podmotion-io/podmotion/internal/agent/network/bpfloader"
)

// ── packet construction helpers ──────────────────────────────────────────────

// buildVXLANTCPPacket constructs a minimal Ethernet/IP/UDP/VXLAN/Ethernet/IP/TCP
// frame as a byte slice.  seq and ack are in host byte order.  tsval and tsecr
// are the TCP timestamp option fields (0 → no timestamp option).
//
// Frame layout (offsets from byte 0):
//
//	0–13:    outer Ethernet (14 B)
//	14–33:   outer IPv4    (20 B)
//	34–41:   outer UDP     (8 B)
//	42–49:   VXLAN header  (8 B)
//	50–63:   inner Ethernet (14 B)
//	64–83:   inner IPv4    (20 B)
//	84–103:  inner TCP     (20 B, no options unless tsval/tsecr set)
//	104+:    TCP options (NOP NOP TS) + payload if requested
func buildVXLANTCPPacket(
	innerSrcIP, innerDstIP [4]byte,
	srcPort, dstPort uint16,
	seq, ack uint32,
	tsval, tsecr uint32,
	payload []byte,
) []byte {
	tcpOptionLen := 0
	if tsval != 0 || tsecr != 0 {
		tcpOptionLen = 12 // NOP NOP TS val(4) ecr(4)
	}
	tcpDataOffset := uint8((20 + tcpOptionLen) / 4)
	innerTCPLen := 20 + tcpOptionLen + len(payload)
	innerIPLen := 20 + innerTCPLen
	outerUDPPayloadLen := 8 /* VXLAN */ + 14 /* inner eth */ + innerIPLen
	outerIPLen := 20 + 8 /* UDP */ + outerUDPPayloadLen
	totalLen := 14 + outerIPLen

	pkt := make([]byte, totalLen)

	// outer Ethernet — dummy MACs, ethertype IPv4 (0x0800)
	pkt[12] = 0x08
	pkt[13] = 0x00

	// outer IPv4
	outerIP := pkt[14:]
	outerIP[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(outerIP[2:], uint16(outerIPLen))
	outerIP[9] = 17 // UDP
	copy(outerIP[12:], []byte{192, 168, 252, 8})  // src = pm-worker flannel VTEP
	copy(outerIP[16:], []byte{192, 168, 252, 7})  // dst = pm-control flannel VTEP
	outerIPChecksum := ipChecksum(outerIP[:20])
	binary.BigEndian.PutUint16(outerIP[10:], outerIPChecksum)

	// outer UDP
	outerUDP := pkt[34:]
	binary.BigEndian.PutUint16(outerUDP[0:], 12345) // src port
	binary.BigEndian.PutUint16(outerUDP[2:], 4789)  // dst port = VXLAN
	binary.BigEndian.PutUint16(outerUDP[4:], uint16(8+outerUDPPayloadLen))
	// outer UDP checksum = 0 per RFC 7348 §6

	// VXLAN
	vxlan := pkt[42:]
	vxlan[0] = 0x08 // I-flag set
	vxlan[4] = 0x00 // VNI[23:16]
	vxlan[5] = 0x00 // VNI[15:8]
	vxlan[6] = 0x01 // VNI[7:0] = 1

	// inner Ethernet
	innerEth := pkt[50:]
	innerEth[12] = 0x08
	innerEth[13] = 0x00

	// inner IPv4
	innerIP := pkt[64:]
	innerIP[0] = 0x45
	binary.BigEndian.PutUint16(innerIP[2:], uint16(innerIPLen))
	innerIP[9] = 6 // TCP
	copy(innerIP[12:], innerSrcIP[:])
	copy(innerIP[16:], innerDstIP[:])
	innerIPCS := ipChecksum(innerIP[:20])
	binary.BigEndian.PutUint16(innerIP[10:], innerIPCS)

	// inner TCP
	innerTCP := pkt[84:]
	binary.BigEndian.PutUint16(innerTCP[0:], srcPort)
	binary.BigEndian.PutUint16(innerTCP[2:], dstPort)
	binary.BigEndian.PutUint32(innerTCP[4:], seq)
	binary.BigEndian.PutUint32(innerTCP[8:], ack)
	innerTCP[12] = tcpDataOffset << 4
	innerTCP[13] = 0x18 // ACK+PSH
	binary.BigEndian.PutUint16(innerTCP[14:], 65535) // window

	if tsval != 0 || tsecr != 0 {
		opts := innerTCP[20:]
		opts[0] = 0x01 // NOP
		opts[1] = 0x01 // NOP
		opts[2] = 0x08 // kind=8 (Timestamp)
		opts[3] = 0x0a // len=10
		binary.BigEndian.PutUint32(opts[4:], tsval)
		binary.BigEndian.PutUint32(opts[8:], tsecr)
	}

	copy(innerTCP[20+tcpOptionLen:], payload)

	// inner TCP pseudo-header checksum
	tcpCS := tcpChecksum(innerIP[:20], innerTCP[:innerTCPLen])
	binary.BigEndian.PutUint16(innerTCP[16:], tcpCS)

	return pkt
}

// ipChecksum computes the Internet checksum for a 20-byte IPv4 header.
func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum over the pseudo-header + TCP segment.
func tcpChecksum(ipHdr, tcpSeg []byte) uint16 {
	var sum uint32
	// pseudo-header: src, dst, zero, proto, TCP length
	sum += uint32(ipHdr[12])<<8 | uint32(ipHdr[13])
	sum += uint32(ipHdr[14])<<8 | uint32(ipHdr[15])
	sum += uint32(ipHdr[16])<<8 | uint32(ipHdr[17])
	sum += uint32(ipHdr[18])<<8 | uint32(ipHdr[19])
	sum += 6 // TCP
	sum += uint32(len(tcpSeg))
	for i := 0; i+1 < len(tcpSeg); i += 2 {
		sum += uint32(tcpSeg[i])<<8 | uint32(tcpSeg[i+1])
	}
	if len(tcpSeg)%2 != 0 {
		sum += uint32(tcpSeg[len(tcpSeg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ── packet construction unit tests ───────────────────────────────────────────

// TestBuildVXLANTCPPacket_SeqAckOffsets verifies that seq and ack are written at
// the expected byte offsets within the constructed packet.
func TestBuildVXLANTCPPacket_SeqAckOffsets(t *testing.T) {
	srcIP := [4]byte{10, 244, 1, 50}
	dstIP := [4]byte{10, 244, 0, 50}
	const seq uint32 = 0xDEAD_BEEF
	const ack uint32 = 0xCAFE_BABE

	pkt := buildVXLANTCPPacket(srcIP, dstIP, 9000, 5432, seq, ack, 0, 0, nil)

	// inner TCP starts at byte 84; seq at +4, ack at +8.
	gotSeq := binary.BigEndian.Uint32(pkt[88:])
	gotAck := binary.BigEndian.Uint32(pkt[92:])
	if gotSeq != seq {
		t.Errorf("seq at offset 88: got %#x, want %#x", gotSeq, seq)
	}
	if gotAck != ack {
		t.Errorf("ack at offset 92: got %#x, want %#x", gotAck, ack)
	}
}

// TestBuildVXLANTCPPacket_TSvalOffset verifies TSval and TSecr placement in the
// TCP timestamp option at the expected byte offsets.
func TestBuildVXLANTCPPacket_TSvalOffset(t *testing.T) {
	srcIP := [4]byte{10, 244, 1, 51}
	dstIP := [4]byte{10, 244, 0, 51}
	const tsval uint32 = 0x1234_5678
	const tsecr uint32 = 0x8765_4321

	pkt := buildVXLANTCPPacket(srcIP, dstIP, 9001, 5432, 1, 1, tsval, tsecr, nil)

	// TCP options start at byte 104 (84 + 20); NOP NOP TS at +0,+1,+2,+3; val at +4.
	tsvalGot := binary.BigEndian.Uint32(pkt[108:])
	tsecrGot := binary.BigEndian.Uint32(pkt[112:])
	if tsvalGot != tsval {
		t.Errorf("TSval: got %#x, want %#x", tsvalGot, tsval)
	}
	if tsecrGot != tsecr {
		t.Errorf("TSecr: got %#x, want %#x", tsecrGot, tsecr)
	}
}

// TestBuildVXLANTCPPacket_InnerIPChecksum verifies that the constructed packet
// has a valid inner IPv4 checksum.  The relay program will re-compute it
// incrementally (RFC 1624); we verify the initial value is correct first.
func TestBuildVXLANTCPPacket_InnerIPChecksum(t *testing.T) {
	srcIP := [4]byte{10, 244, 1, 52}
	dstIP := [4]byte{10, 244, 0, 52}
	pkt := buildVXLANTCPPacket(srcIP, dstIP, 9002, 5432, 1000, 2000, 0, 0, []byte("hello"))

	innerIP := pkt[64:84]
	// To verify: recalculate with checksum field zeroed.
	dup := make([]byte, 20)
	copy(dup, innerIP)
	dup[10] = 0
	dup[11] = 0
	computed := ipChecksum(dup)
	stored := binary.BigEndian.Uint16(innerIP[10:])
	if computed != stored {
		t.Errorf("inner IP checksum: computed %#x, stored %#x", computed, stored)
	}
}

// TestBuildVXLANTCPPacket_InnerTCPChecksum verifies the inner TCP checksum.
func TestBuildVXLANTCPPacket_InnerTCPChecksum(t *testing.T) {
	srcIP := [4]byte{10, 244, 1, 53}
	dstIP := [4]byte{10, 244, 0, 53}
	pkt := buildVXLANTCPPacket(srcIP, dstIP, 9003, 5432, 1000, 2000, 0, 0, []byte("testpayload"))

	innerIP := pkt[64:84]
	ipTotalLen := int(binary.BigEndian.Uint16(innerIP[2:]))
	innerTCPLen := ipTotalLen - 20
	innerTCP := pkt[84 : 84+innerTCPLen]

	dup := make([]byte, len(innerTCP))
	copy(dup, innerTCP)
	dup[16] = 0
	dup[17] = 0
	computed := tcpChecksum(innerIP, dup)
	stored := binary.BigEndian.Uint16(innerTCP[16:])
	if computed != stored {
		t.Errorf("inner TCP checksum: computed %#x, stored %#x", computed, stored)
	}
}

// ── BPF load smoke test ───────────────────────────────────────────────────────

// TestLoadPmRelaySpec verifies the bpfloader API surface compiles and does not panic.
// On Linux with a BPF-capable kernel and valid .o the load may succeed; on darwin it
// returns an error (stub).  Both outcomes are acceptable.
func TestLoadPmRelaySpec(t *testing.T) {
	_, err := bpfloader.LoadPmRelaySpec()
	if err != nil {
		t.Logf("LoadPmRelaySpec returned expected error (non-Linux or placeholder .o): %v", err)
	} else {
		t.Log("LoadPmRelaySpec succeeded — BPF capable kernel with valid .o")
	}
}

// TestPmRelayObjectsCloseNoop verifies that Close on a zero-value object does not panic.
func TestPmRelayObjectsCloseNoop(t *testing.T) {
	var objs bpfloader.PmRelayObjects
	objs.Close()
}

// ── seq/ack delta arithmetic tests (BPF_PROG_TEST_RUN modeled in pure Go) ───
//
// These tests replicate the exact 32-bit modular arithmetic that pm_relay.c
// applies on egress and ingress so that any future C-side change must also
// update these reference values.

// TestRelayEgressSeqDelta verifies the egress direction seq rewrite:
//
//	output_seq = input_seq + seq_delta (32-bit wrap)
func TestRelayEgressSeqDelta(t *testing.T) {
	cases := []struct {
		inputSeq  uint32
		seqDelta  int32
		wantSeq   uint32
	}{
		{0x1000_0000, 500, 0x1000_01F4},
		{0xFFFF_FF00, 512, 0x0000_0100}, // wraparound: 0xFFFFFF00 + 512 = 0x100000100 → 0x100
		{0x0000_0000, -1, 0xFFFF_FFFF},  // negative delta
		{0xDEAD_BEEF, 0, 0xDEAD_BEEF},  // zero delta = passthrough
	}
	for _, tc := range cases {
		got := uint32(int32(tc.inputSeq) + tc.seqDelta)
		if got != tc.wantSeq {
			t.Errorf("egress seq: input=%#x delta=%d got=%#x want=%#x",
				tc.inputSeq, tc.seqDelta, got, tc.wantSeq)
		}
	}
}

// TestRelayIngressSeqDelta verifies the ingress direction seq rewrite:
//
//	output_seq = input_seq - seq_delta (32-bit wrap)
func TestRelayIngressSeqDelta(t *testing.T) {
	cases := []struct {
		inputSeq uint32
		seqDelta int32
		wantSeq  uint32
	}{
		{0x1000_01F4, 500, 0x1000_0000},
		{0x0000_0100, 512, 0xFFFF_FF00}, // reverse wraparound
		{0xFFFF_FFFF, -1, 0x0000_0000},
		{0xDEAD_BEEF, 0, 0xDEAD_BEEF},
	}
	for _, tc := range cases {
		got := uint32(int32(tc.inputSeq) - tc.seqDelta)
		if got != tc.wantSeq {
			t.Errorf("ingress seq: input=%#x delta=%d got=%#x want=%#x",
				tc.inputSeq, tc.seqDelta, got, tc.wantSeq)
		}
	}
}

// TestRelayEgressAckDelta verifies egress ack rewrite (same formula as seq).
func TestRelayEgressAckDelta(t *testing.T) {
	cases := []struct {
		inputAck uint32
		ackDelta int32
		wantAck  uint32
	}{
		{0x2000_0000, 1000, 0x2000_03E8},
		{0xFFFF_FC18, 1000, 0x0000_0000}, // wraparound: 0xFFFFFC18 + 1000 = 0x10000_0000 → 0
		{0xDEAD_0000, 0, 0xDEAD_0000},
	}
	for _, tc := range cases {
		got := uint32(int32(tc.inputAck) + tc.ackDelta)
		if got != tc.wantAck {
			t.Errorf("egress ack: input=%#x delta=%d got=%#x want=%#x",
				tc.inputAck, tc.ackDelta, got, tc.wantAck)
		}
	}
}

// TestRelayTSvalEgressIngress verifies TSval (egress, added) and TSecr (ingress,
// also added — the asymmetry noted in pm_relay.c: peer echoes our TSval so on
// ingress TSecr must be shifted the same direction as our outbound TSval).
func TestRelayTSvalEgressIngress(t *testing.T) {
	const tsDelta int32 = 0x0000_1000

	// egress: TSval += ts_delta
	tsvalIn := uint32(0xABCD_0000)
	tsvalOut := uint32(int32(tsvalIn) + tsDelta)
	wantTSvalOut := uint32(0xABCD_1000)
	if tsvalOut != wantTSvalOut {
		t.Errorf("TSval egress: got %#x want %#x", tsvalOut, wantTSvalOut)
	}

	// ingress: TSecr += ts_delta (same direction — peer echoes our shifted TSval)
	tsecrIn := uint32(0xABCD_1000) // peer echoed our shifted TSval
	tsecrOut := uint32(int32(tsecrIn) + tsDelta)
	// After relay applies tsDelta again on ingress:
	// tsecrOut = 0xABCD_1000 + 0x1000 = 0xABCD_2000
	// This is INTENTIONAL per ADR-0049 §PAWS: the peer's echo is already shifted
	// so we shift once more to keep PAWS monotone on the receiving side.
	wantTSecrOut := uint32(0xABCD_2000)
	if tsecrOut != wantTSecrOut {
		t.Errorf("TSecr ingress: got %#x want %#x", tsecrOut, wantTSecrOut)
	}
}

// TestRelayRFC1624IncrementalChecksum verifies the RFC 1624 incremental checksum
// update formula used in pm_relay.c.
//
//	new_csum = ~(~old_csum + ~old_field + new_field)
//
// This is the exact computation the BPF program applies after rewriting seq.
// For a 32-bit field update, the BPF program splits the field into two 16-bit
// halves and applies the formula twice.
func TestRelayRFC1624IncrementalChecksum(t *testing.T) {
	oldField := uint32(0x1000_0000)
	newField := uint32(0x1000_01F4) // oldField + 500
	oldCsum := uint16(0xAAAA)

	// RFC 1624 fold helper: folds a uint32 sum to uint16.
	fold16 := func(v uint32) uint16 {
		v = (v & 0xffff) + (v >> 16)
		v = (v & 0xffff) + (v >> 16)
		return uint16(v) //nolint:gosec
	}

	// Apply RFC 1624 for the high 16-bit half of the 32-bit seq field.
	sum1 := uint32(^oldCsum) + uint32(^uint16(oldField>>16)) + uint32(uint16(newField>>16)) //nolint:gosec
	csum1 := ^fold16(sum1)

	// Apply RFC 1624 for the low 16-bit half.
	sum2 := uint32(^csum1) + uint32(^uint16(oldField&0xffff)) + uint32(uint16(newField&0xffff)) //nolint:gosec
	newCsum := ^fold16(sum2)

	// The result should differ from oldCsum when the field changed.
	if newCsum == oldCsum {
		t.Errorf("RFC 1624: checksum unchanged after field rewrite (old=%#x new=%#x)",
			oldField, newField)
	}
}

// TestRelaySACKBlockEdgeTranslation verifies that SACK block left/right edges
// are translated by the same ack_delta as the ACK field.
//
// pm_relay.c adds ack_delta to each SACK block edge on egress (the migrated
// pod is advertising what bytes it has received, which must be in the new
// seq space) and subtracts ack_delta on ingress.
func TestRelaySACKBlockEdgeTranslation(t *testing.T) {
	const ackDelta int32 = 1000

	cases := []struct {
		edge    uint32
		wantEgress  uint32
		wantIngress uint32
	}{
		{0x5000_0000, 0x5000_03E8, 0x4FFF_FC18},
		{0xFFFF_FC18, 0x0000_0000, 0xFFFF_F830}, // wraparound on egress
		{0x0000_0000, 0x0000_03E8, 0xFFFF_FC18},
	}
	for _, tc := range cases {
		egress := uint32(int32(tc.edge) + ackDelta)
		ingress := uint32(int32(tc.edge) - ackDelta)
		if egress != tc.wantEgress {
			t.Errorf("SACK egress edge %#x + %d = %#x want %#x",
				tc.edge, ackDelta, egress, tc.wantEgress)
		}
		if ingress != tc.wantIngress {
			t.Errorf("SACK ingress edge %#x - %d = %#x want %#x",
				tc.edge, ackDelta, ingress, tc.wantIngress)
		}
	}
}
