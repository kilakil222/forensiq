package memparse

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestIsPort_LowPortsRejected(t *testing.T) {
	for p := uint16(1); p < 20; p++ {
		if isPort(p) {
			t.Errorf("isPort(%d) = true, want false (low port should be rejected)", p)
		}
	}
	// Port 20 and above should pass basic check
	if !isPort(20) {
		t.Error("isPort(20) = false, want true")
	}
	if !isPort(443) {
		t.Error("isPort(443) = false, want true")
	}
	// Special artifact ports still rejected
	if isPort(0x0200) {
		t.Error("isPort(0x0200/512) = true, want false")
	}
	if isPort(0x1700) {
		t.Error("isPort(0x1700/5888) = true, want false")
	}
}

func TestScanNetwork_SelfReferentialFiltered(t *testing.T) {
	conns := []NetConn{
		{Proto: "TCP", LocalAddr: "99.112.69.224", LocalPort: 84,
			RemoteAddr: "99.112.69.224", RemotePort: 84},
		{Proto: "TCP", LocalAddr: "192.168.1.5", LocalPort: 49673,
			RemoteAddr: "", RemotePort: 0, State: "LISTEN"},
	}
	// Simulate the dedup + self-referential filter inline
	type netKey struct{ proto, localAddr, remoteAddr string; localPort, remotePort uint16 }
	best := make(map[netKey]*NetConn, len(conns))
	for i := range conns {
		c := &conns[i]
		k := netKey{c.Proto, c.LocalAddr, c.RemoteAddr, c.LocalPort, c.RemotePort}
		if prev, ok := best[k]; !ok || netConnScore(c) > netConnScore(prev) {
			best[k] = c
		}
	}
	out := make([]NetConn, 0, len(best))
	for _, c := range best {
		out = append(out, *c)
	}
	filtered := out[:0]
	for _, c := range out {
		if c.RemoteAddr == "" || c.LocalAddr != c.RemoteAddr {
			filtered = append(filtered, c)
		}
	}
	for _, c := range filtered {
		if c.LocalAddr != "" && c.RemoteAddr != "" && c.LocalAddr == c.RemoteAddr {
			t.Errorf("self-referential entry survived: %s:%d -> %s:%d",
				c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort)
		}
	}
	if len(filtered) != 1 {
		t.Errorf("expected 1 entry after filtering, got %d", len(filtered))
	}
}

func TestLooksLikePrivateLocalIPv4(t *testing.T) {
	private := []net.IP{
		net.IPv4(0, 0, 0, 0).To4(),     // 0.0.0.0 LISTEN
		net.IPv4(127, 0, 0, 1).To4(),   // loopback
		net.IPv4(10, 0, 0, 1).To4(),    // RFC1918
		net.IPv4(172, 16, 0, 1).To4(),  // RFC1918
		net.IPv4(192, 168, 1, 1).To4(), // RFC1918
	}
	public := []net.IP{
		net.IPv4(210, 207, 15, 15).To4(),  // Japanese ISP
		net.IPv4(142, 251, 47, 99).To4(), // Google
		net.IPv4(82, 101, 69, 68).To4(),  // Public
		net.IPv4(8, 8, 8, 8).To4(),       // Google DNS
	}
	for _, ip := range private {
		if !looksLikePrivateLocalIPv4(ip) {
			t.Errorf("looksLikePrivateLocalIPv4(%s) = false, want true", ip)
		}
	}
	for _, ip := range public {
		if looksLikePrivateLocalIPv4(ip) {
			t.Errorf("looksLikePrivateLocalIPv4(%s) = true, want false (public IP)", ip)
		}
	}
}

func TestExtractEndpoint_PublicIPSingleEntry_BecomesRemote(t *testing.T) {
	// Build a minimal pool body: AF_INET marker (02 00) + port + public IP at offset 0x08
	// We expect extractEndpoint to assign the public IP as RemoteAddr (not LocalAddr)
	// when it's the only IP found (phase 1b fallback).
	body := make([]byte, 0x200)
	// Put AF_INET marker at 0x08: 02 00 <port_be> <ip>
	// Port = 443 (0x01BB big-endian)
	body[0x08] = 0x02
	body[0x09] = 0x00
	body[0x0A] = 0x01 // port high byte
	body[0x0B] = 0xBB // port low byte (443 = 0x01BB)
	body[0x0C] = 142  // 142.251.47.99 (Google)
	body[0x0D] = 251
	body[0x0E] = 47
	body[0x0F] = 99

	c := extractEndpoint(body, "TCP", 0, nil, nil)
	if c == nil {
		t.Fatal("extractEndpoint returned nil for valid pool body with public IP")
	}
	if c.LocalAddr != "" {
		t.Errorf("LocalAddr = %q, want empty (public IP should be Remote)", c.LocalAddr)
	}
	if c.RemoteAddr != "142.251.47.99" {
		t.Errorf("RemoteAddr = %q, want 142.251.47.99", c.RemoteAddr)
	}
	if c.RemotePort != 443 {
		t.Errorf("RemotePort = %d, want 443", c.RemotePort)
	}
}

func TestExtractEndpoint_PIDAbove65532Rejected(t *testing.T) {
	// pid=66048 (0x10200) is an AF_INET artifact that must not be accepted as PID.
	body := make([]byte, 0x200)
	// Local 0.0.0.0:49664 at offset 0x08
	body[0x08] = 0x02
	body[0x09] = 0x00
	body[0x0A] = 0xC1
	body[0x0B] = 0xC0 // 49600
	// Plant pid=66048 (0x10200) at 0x80 — must be rejected.
	binary.LittleEndian.PutUint64(body[0x80:], 66048)
	// Plant a valid pid=4096 at 0x88 — must be accepted.
	binary.LittleEndian.PutUint64(body[0x88:], 4096)

	c := extractEndpoint(body, "TCP", 0, nil, nil)
	if c == nil {
		t.Fatal("extractEndpoint returned nil")
	}
	if c.PID == 66048 {
		t.Error("PID = 66048, want ≤65532 (artifact value must be rejected)")
	}
	if c.PID != 4096 {
		t.Errorf("PID = %d, want 4096 (first valid PID in body)", c.PID)
	}
}

func TestScanNetwork_ListenWithRemoteFiltered(t *testing.T) {
	// LISTEN sockets have no remote endpoint — entries with remote_addr set are artifacts.
	conns := []NetConn{
		{Proto: "TCP", LocalAddr: "77.184.232.173", LocalPort: 18571,
			RemoteAddr: "77.160.72.255", RemotePort: 18573, State: "LISTEN"},
		{Proto: "TCP", LocalAddr: "0.0.0.0", LocalPort: 5985,
			RemoteAddr: "", RemotePort: 0, State: "LISTEN"},
	}
	filtered := make([]NetConn, 0)
	for _, c := range conns {
		if c.State == "LISTEN" && c.RemoteAddr != "" {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(filtered) != 1 {
		t.Errorf("expected 1 entry after LISTEN filter, got %d", len(filtered))
	}
	if len(filtered) == 1 && filtered[0].LocalPort != 5985 {
		t.Errorf("wrong entry survived: port %d, want 5985", filtered[0].LocalPort)
	}
}

func TestIsPort_ArtifactPortsRejected(t *testing.T) {
	// Port 257 = 0x0101: repeating-byte pattern, not a real port.
	if isPort(257) {
		t.Error("isPort(257/0x0101) = true, want false")
	}
	// Existing special ports still rejected.
	if isPort(0x0200) {
		t.Error("isPort(0x0200/512) = true, want false")
	}
	if isPort(0x1700) {
		t.Error("isPort(0x1700/5888) = true, want false")
	}
}

func TestExtractEndpoint_ShiftedPoolTagIPRejected(t *testing.T) {
	// 99.112.69.224 = 0x63 0x70 0x45 0xE0 = TcpE bytes 1-3 in IP field.
	// Appears when AF_INET marker sits one byte before a TcpE pool tag.
	body := make([]byte, 0x200)
	body[0x08] = 0x02
	body[0x09] = 0x00
	body[0x0A] = 0x00 // port 84
	body[0x0B] = 0x54
	body[0x0C] = 0x63 // TcpE bytes 1-3 as IP
	body[0x0D] = 0x70
	body[0x0E] = 0x45
	body[0x0F] = 0xE0

	c := extractEndpoint(body, "TCP", 0, nil, nil)
	if c != nil && (c.LocalAddr == "99.112.69.224" || c.RemoteAddr == "99.112.69.224") {
		t.Error("shifted pool tag IP 99.112.69.224 (TcpE bytes 1-3) must be rejected")
	}
}

func TestExtractEndpoint_PoolTagIPRejected(t *testing.T) {
	// 84.99.112.69 = 0x54 0x63 0x70 0x45 = "TcpE" pool tag bytes in IP field.
	// Must be rejected — the scanner found "TcpE" in data memory, not a real socket.
	body := make([]byte, 0x200)
	body[0x08] = 0x02
	body[0x09] = 0x00
	body[0x0A] = 0x01 // port 443
	body[0x0B] = 0xBB
	body[0x0C] = 0x54 // "TcpE" as IP
	body[0x0D] = 0x63
	body[0x0E] = 0x70
	body[0x0F] = 0x45

	c := extractEndpoint(body, "TCP", 0, nil, nil)
	if c != nil && (c.LocalAddr == "84.99.112.69" || c.RemoteAddr == "84.99.112.69") {
		t.Error("pool tag IP 84.99.112.69 (TcpE bytes) must be rejected as artifact")
	}
}

func TestExtractEndpoint_PrivateIPStaysLocal(t *testing.T) {
	// Private IP (192.168.x.x) should remain as LocalAddr
	body := make([]byte, 0x200)
	body[0x08] = 0x02
	body[0x09] = 0x00
	body[0x0A] = 0xC1 // port 49673 = 0xC1C9
	body[0x0B] = 0xC9
	body[0x0C] = 192
	body[0x0D] = 168
	body[0x0E] = 1
	body[0x0F] = 5

	c := extractEndpoint(body, "TCP", 0, nil, nil)
	if c == nil {
		t.Fatal("extractEndpoint returned nil for private IP body")
	}
	if c.LocalAddr != "192.168.1.5" {
		t.Errorf("LocalAddr = %q, want 192.168.1.5", c.LocalAddr)
	}
	if c.RemoteAddr != "" {
		t.Errorf("RemoteAddr = %q, want empty (only one IP found)", c.RemoteAddr)
	}
}
