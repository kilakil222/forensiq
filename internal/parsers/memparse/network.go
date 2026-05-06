package memparse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// NetConn is one extracted endpoint, TCP or UDP.
type NetConn struct {
	Proto      string
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	State      string
	PID        uint64
	Owner      string
	Offset     uint64
	CreateTime time.Time
}

var tcpStates = map[uint8]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN-SENT",
	4:  "SYN-RECEIVED",
	5:  "ESTABLISHED",
	6:  "FIN-WAIT-1",
	7:  "FIN-WAIT-2",
	8:  "CLOSE-WAIT",
	9:  "CLOSING",
	10: "LAST-ACK",
	11: "TIME-WAIT",
	12: "DELETE-TCB",
}

// scanNetwork scans physical memory for TcpE/UdpA pool tags and emits heuristic
// connection records. The TCP/UDP endpoint structures move every Windows build
// so we extract IP+port pairs by pattern, not fixed offsets — this is fuzzy
// but resilient. kernCR3/p/vread are forwarded to extractEndpoint so it can
// try to resolve the owning process name directly from the pool block.
func scanNetwork(d *Dump, kernCR3 uint64, p *WinProfile, vread vreadFn) []NetConn {
	conns := make([]NetConn, 0, 64)
	tcpTag  := []byte{0x54, 0x63, 0x70, 0x45} // "TcpE"
	tcpLTag := []byte{0x54, 0x63, 0x70, 0x4C} // "TcpL" — TCP listener (LISTEN state)
	udpTag  := []byte{0x55, 0x64, 0x70, 0x41} // "UdpA"
	udpBTag := []byte{0x55, 0x64, 0x70, 0x42} // "UdpB"
	udpCTag := []byte{0x55, 0x64, 0x70, 0x43} // "UdpC"
	seen := map[uint64]bool{}

	const chunkSize = 0x10000
	for _, run := range d.runs {
		runStart := run.BasePage * pageSize
		runLen := run.PageCount * pageSize
		var off uint64
		for off < runLen {
			read := chunkSize
			if uint64(read) > runLen-off {
				read = int(runLen - off)
			}
			page := d.ReadPhys(runStart+off, read)
			if len(page) == 0 {
				off += uint64(read)
				continue
			}

			scanTag := func(pat []byte, proto string) {
				start := 0
				for {
					idx := bytes.Index(page[start:], pat)
					if idx < 0 {
						break
					}
					tagPA := runStart + off + uint64(start+idx)
					start += idx + 1
					if seen[tagPA] {
						continue
					}
					seen[tagPA] = true
					// Read 0x400 bytes after the tag and pattern-extract.
					body := d.ReadPhys(tagPA, 0x400)
					if len(body) < 0x80 {
						continue
					}
					if c := extractEndpoint(body, proto, kernCR3, p, vread); c != nil {
	
						if proto == "UDP" && c.PID == 0 && c.RemoteAddr != "" && c.RemoteAddr != "0.0.0.0" {
							continue
						}
						// TCPL = TCP listener: must have a local addr, drop obvious noise.
						if proto == "TCPL" {
							if c.LocalAddr == "" {
								continue
							}
							c.Proto = "TCP"
						}
						c.Offset = tagPA
						conns = append(conns, *c)
						if len(conns) >= 4096 {
							return
						}
					}
				}
			}
			scanTag(tcpTag, "TCP")
			scanTag(tcpLTag, "TCPL")
			scanTag(udpTag, "UDP")
			scanTag(udpBTag, "UDP")
			scanTag(udpCTag, "UDP")
			if len(conns) >= 4096 {
				return conns
			}
			off += uint64(read)
		}
	}
	// Deduplicate: the same endpoint appears in multiple freed pool blocks
	// (e.g. two freed TcpE blocks for the same CLOSED connection, or both a
	// TcpE and a TcpL block for the same listener). Key = exact 5-tuple.
	// When duplicates exist keep the entry with the highest quality score:
	// prefer ESTABLISHED > LISTEN > ... > CLOSED > empty state, then non-zero
	// PID, then non-empty owner name.
	type netKey struct {
		proto, localAddr, remoteAddr string
		localPort, remotePort        uint16
	}
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
	// Remove self-referential entries: a TCP connection where local IP == remote IP
	// is networking-impossible and is always a pool artifact.
	// Also remove LISTEN entries with a non-empty remote address: LISTEN sockets
	// have no remote endpoint by definition; such entries are pool artifacts.
	filtered := out[:0]
	for _, c := range out {
		if c.RemoteAddr != "" && c.LocalAddr == c.RemoteAddr {
			continue
		}
		if c.State == "LISTEN" && c.RemoteAddr != "" {
			continue
		}
		filtered = append(filtered, c)
	}
	return filtered
}

// netStatePri maps a TCP state string to a priority integer so that more
// informative states win deduplication over CLOSED / empty.
func netStatePri(state string) int {
	switch state {
	case "ESTABLISHED":
		return 7
	case "LISTEN":
		return 6
	case "SYN-SENT", "SYN-RECEIVED":
		return 5
	case "FIN-WAIT-1", "FIN-WAIT-2":
		return 4
	case "CLOSE-WAIT", "CLOSING", "LAST-ACK", "TIME-WAIT":
		return 3
	case "CLOSED":
		return 2
	case "DELETE-TCB":
		return 1
	default:
		return 0
	}
}

// netConnScore scores a NetConn for deduplication: prefer rich data over sparse.
func netConnScore(c *NetConn) int {
	score := netStatePri(c.State)
	if c.PID != 0 {
		score += 4
	}
	if c.Owner != "" {
		score += 2
	}
	return score
}

// extractEndpoint parses a 0x400-byte window after a TcpE/TcpL/UdpA pool tag.
//
// On Windows 10 x64, TCP_ENDPOINT structures store addresses as sockaddr_in-like
// patterns: [02 00] (AF_INET LE) + [port BE 2 bytes] + [IPv4 4 bytes].
// IPv6 endpoints use: [17 00] (AF_INET6 LE) + [port BE 2] + [flowinfo 4] + [IPv6 16].
// TcpE scan starts at +0x50 (past pool header and early kernel pointers).
// TcpL (TCP_LISTENER) scan starts at +0x10 — the listener structure is simpler
// and the bound address appears earlier in the pool block.
func extractEndpoint(body []byte, proto string, kernCR3 uint64, p *WinProfile, vread vreadFn) *NetConn {
	c := &NetConn{Proto: proto}

	// Look for AF_INET/AF_INET6 sockaddr patterns.
	// TCP_ENDPOINT structure begins at body[8] (pool tag at 0–3, last 4 bytes
	// of pool header at 4–7). UDP_ENDPOINT has more header before the address,
	// so use 0x10 for UDP to avoid false AF_INET hits in early struct fields.
	scanStart := 0x08
	if proto == "UDP" {
		scanStart = 0x10
	}

	type sockEntry struct {
		port uint16
		ip   net.IP
	}
	var entries []sockEntry

	// Pass 1: AF_INET (IPv4), two phases for the first (local) address.
	// Phase 1a (strict): prefer 0.0.0.0/loopback/private IPs as the local bind.
	// Phase 1b (relaxed): fall back to any valid IP only if nothing private found.
	// This prevents a remote public IP appearing early in the freed pool block from
	// masquerading as the local socket address.
	for _, strictLocal := range []bool{true, false} {
		if len(entries) > 0 {
			break
		}
		for i := scanStart; i+8 <= len(body); i++ {
			if body[i] != 0x02 || body[i+1] != 0x00 {
				continue
			}
			port := binary.BigEndian.Uint16(body[i+2 : i+4])
			if !isPort(port) {
				continue
			}
			ip := net.IPv4(body[i+4], body[i+5], body[i+6], body[i+7]).To4()
			var ipOK bool
			if len(entries) == 0 {
				if strictLocal {
					ipOK = looksLikePrivateLocalIPv4(ip)
				} else {
					ipOK = looksLikeLocalIPv4(ip)
				}
			} else {
				ipOK = looksLikeIPv4(ip)
			}
			if !ipOK {
				continue
			}
			entries = append(entries, sockEntry{port: port, ip: ip})
			if len(entries) >= 2 {
				break
			}
		}
	}

	// Pass 2: AF_INET6, only if no IPv4 addresses were found above.
	// Pattern: 17 00 <port_be_2> <flowinfo_4> <ipv6_16> = 24 bytes.
	if len(entries) == 0 {
		for i := scanStart; i+24 <= len(body); i++ {
			if body[i] != 0x17 || body[i+1] != 0x00 {
				continue
			}
			port := binary.BigEndian.Uint16(body[i+2 : i+4])
			if !isPort(port) {
				continue
			}
			ip6 := make(net.IP, 16)
			copy(ip6, body[i+8:i+24])
			var ipOK bool
			if len(entries) == 0 {
				ipOK = looksLikeLocalIPv6(ip6)
			} else {
				ipOK = looksLikeIPv6(ip6)
			}
			if !ipOK {
				continue
			}
			entries = append(entries, sockEntry{port: port, ip: ip6})
			if len(entries) >= 2 {
				break
			}
		}
	}

	// Fallback: if no inline address found, scan pool block for kernel pointers and
	// dereference each via vread. Only for TCP — UDP endpoints have inline addresses
	// and pointer-deref generates false positives for UDP pool blocks.
	if len(entries) == 0 && (proto == "TCP" || proto == "TCPL") && kernCR3 != 0 && vread != nil {
		tried := 0
		for i := 0x08; i+8 <= len(body) && i < 0x300 && tried < 40; i += 4 {
			ptr := binary.LittleEndian.Uint64(body[i : i+8])
			if !isKernelAddr(ptr) {
				continue
			}
			tried++
			buf := vread(kernCR3, ptr, 64) // 64 = covers sockaddr at any offset in target struct
			if len(buf) < 8 {
				continue
			}
			for j := 0; j+8 <= len(buf); j++ {
				if buf[j+1] != 0x00 {
					continue
				}
				fam := buf[j]
				if fam == 0x02 { // AF_INET
					port := binary.BigEndian.Uint16(buf[j+2 : j+4])
					if !isPort(port) {
						continue
					}
					ip := net.IPv4(buf[j+4], buf[j+5], buf[j+6], buf[j+7]).To4()
					var ipOK bool
					if len(entries) == 0 {
						ipOK = looksLikeLocalIPv4(ip)
					} else {
						ipOK = looksLikeIPv4(ip)
					}
					if !ipOK {
						continue
					}
					entries = append(entries, sockEntry{port: port, ip: ip})
					break
				} else if fam == 0x17 && j+24 <= len(buf) { // AF_INET6
					port := binary.BigEndian.Uint16(buf[j+2 : j+4])
					if !isPort(port) {
						continue
					}
					ip6 := make(net.IP, 16)
					copy(ip6, buf[j+8:j+24])
					var ipOK bool
					if len(entries) == 0 {
						ipOK = looksLikeLocalIPv6(ip6)
					} else {
						ipOK = looksLikeIPv6(ip6)
					}
					if !ipOK {
						continue
					}
					entries = append(entries, sockEntry{port: port, ip: ip6})
					break
				}
			}
			if len(entries) >= 2 {
				break
			}
		}
	}

	if len(entries) == 0 {
		return nil
	}
	// Single-entry heuristic: if only one IPv4 address was found and it is a
	// public IP (not 0.0.0.0, loopback, or RFC-1918 private), the local endpoint
	// was not found in this pool block. Assign it as the remote address instead —
	// "machine connected to 142.251.47.99:443" is accurate; calling Google's IP
	// the local socket address is misleading. Private-first addresses (0.0.0.0,
	// 127.x, 10.x, 172.16-31.x, 192.168.x) are genuine local binds and stay local.
	if len(entries) == 1 {
		ip4 := entries[0].ip.To4()
		if ip4 != nil && !looksLikePrivateLocalIPv4(ip4) {
			// Public IP found alone — treat as remote; local side is unknown.
			c.RemoteAddr = ip4.String()
			c.RemotePort = entries[0].port
		} else {
			c.LocalAddr = entries[0].ip.String()
			c.LocalPort = entries[0].port
		}
	} else {
		c.LocalAddr = entries[0].ip.String()
		c.LocalPort = entries[0].port
		c.RemoteAddr = entries[1].ip.String()
		c.RemotePort = entries[1].port
	}

	// TCP state: look for state value in [1,12] at offsets 0x08..0x50.
	// Strategy: first try uint32 at stride 4 (works for CLOSED/old builds),
	// then fall back to individual bytes at stride 1 (works for ESTABLISHED).
	if proto == "TCP" {
		for i := 8; i+4 <= 0x50 && i+4 <= len(body); i += 4 {
			v := binary.LittleEndian.Uint32(body[i : i+4])
			if v >= 1 && v <= 12 {
				if s, ok := tcpStates[uint8(v)]; ok {
					c.State = s
					break
				}
			}
		}
		// Byte-level fallback for builds where state is stored as a single byte.
		if c.State == "" {
			for i := 8; i < 0x50 && i < len(body); i++ {
				b := body[i]
				if b >= 1 && b <= 12 {
					// Require the surrounding bytes to be zero (not inside a pointer).
					if i+3 < len(body) && body[i+1] == 0 && body[i+2] == 0 && body[i+3] == 0 {
						if s, ok := tcpStates[b]; ok {
							c.State = s
							break
						}
					}
				}
			}
		}
	}
	// TcpL pool tag = TCP_LISTENER — always LISTEN state.
	if proto == "TCPL" && c.State == "" {
		c.State = "LISTEN"
	}

	// Owner PID: Windows PIDs are always multiples of 4, range [4, 65532].
	// Windows PIDs are 16-bit values (max 0xFFFC); values above 65535 are pool
	// artifacts (e.g. AF_INET marker 0x0200 shifted into a wider read).
	for i := 0x80; i+8 <= len(body); i += 8 {
		v := binary.LittleEndian.Uint64(body[i : i+8])
		if v >= 4 && v <= 65532 && v%4 == 0 && v != uint64(c.LocalPort) && v != uint64(c.RemotePort) {
			c.PID = v
			break
		}
	}

	// Try to resolve the owning process name directly from the pool block by
	// scanning for an embedded EPROCESS pointer and reading ImageFileName.
	// This works even for terminated processes whose PID is no longer in pslist.
	if c.Owner == "" && kernCR3 != 0 && p != nil && vread != nil {
		c.Owner = eprocNameFromPool(body, c.PID, kernCR3, p, vread)
	}

	// Connection creation FILETIME: 8-byte LE value in the valid timestamp range.
	// Scan at 4-byte stride — the field may not be 8-byte aligned in all builds.
	const (
		ftMin   = uint64(125911584000000000) // 2000-01-01 UTC
		ftMax   = uint64(134774112000000000) // 2028-01-01 UTC
		ftEpoch = uint64(116444736000000000) // 1970-01-01 UTC
	)
	for i := 0x08; i+8 <= len(body); i += 4 {
		ft := binary.LittleEndian.Uint64(body[i : i+8])
		if ft >= ftMin && ft <= ftMax {
			c.CreateTime = time.Unix(0, int64((ft-ftEpoch)*100)).UTC()
			break
		}
	}

	return c
}

// eprocNameFromPool scans the first 0x120 bytes of a TCP/UDP endpoint pool block
// for kernel pointers. For each candidate it validates by checking that the
// EPROCESS PID field matches the expected pid, then reads ImageFileName.
// This correctly identifies the owning process even for terminated processes
// not present in pslist or psscan.
func eprocNameFromPool(body []byte, pid uint64, kernCR3 uint64, p *WinProfile, vread vreadFn) string {
	if p.EProcName <= 0 || p.EProcPID <= 0 {
		return ""
	}
	limit := len(body)
	if limit > 0x120 {
		limit = 0x120
	}
	for i := 0; i+8 <= limit; i += 4 {
		ptr := binary.LittleEndian.Uint64(body[i : i+8])
		if !isKernelAddr(ptr) {
			continue
		}
		// Validate: the PID field of the candidate EPROCESS must match.
		// This prevents misreading non-EPROCESS kernel objects.
		if pid != 0 {
			pidBuf := vread(kernCR3, ptr+uint64(p.EProcPID), 8)
			if len(pidBuf) < 8 {
				continue
			}
			if binary.LittleEndian.Uint64(pidBuf) != pid {
				continue
			}
		}
		nameBuf := vread(kernCR3, ptr+uint64(p.EProcName), 15)
		if len(nameBuf) == 0 {
			continue
		}
		end, hasAlpha := 0, false
		for end < len(nameBuf) && nameBuf[end] >= 0x20 && nameBuf[end] < 0x7F {
			b := nameBuf[end]
			if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
				hasAlpha = true
			}
			end++
		}
		// Require ≥4 chars and first char must be alphanumeric — rejects pool
		// artifacts like " C", "I#", "ZV", "exe", ".exe" that pass the 2-char check.
		firstOK := end > 0 && ((nameBuf[0] >= 'a' && nameBuf[0] <= 'z') || (nameBuf[0] >= 'A' && nameBuf[0] <= 'Z') || (nameBuf[0] >= '0' && nameBuf[0] <= '9'))
		if end >= 4 && hasAlpha && firstOK {
			return string(nameBuf[:end])
		}
	}
	return ""
}

// looksLikePrivateLocalIPv4 accepts only addresses that are unambiguously a
// local bind: 0.0.0.0 (all interfaces), loopback, or RFC-1918 private ranges.
// Used as the preferred (strict) first-pass validator for the local address slot
// so that remote public IPs appearing earlier in a freed pool block do not get
// mistakenly identified as the local socket address.
func looksLikePrivateLocalIPv4(ip net.IP) bool {
	if ip == nil || len(ip) != 4 {
		return false
	}
	a := ip[0]
	if a == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 {
		return true // 0.0.0.0 = LISTEN all interfaces
	}
	if a == 127 {
		return true // loopback
	}
	if a == 10 {
		return true // Class A private
	}
	if a == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true // Class B private
	}
	if a == 192 && ip[1] == 168 {
		return true // Class C private
	}
	return false
}

// looksLikeLocalIPv4 accepts addresses that a Windows socket can be bound to:
// 0.0.0.0 (all interfaces), 127.x.x.x (loopback), private ranges with any
// octet values (10.x, 172.16-31.x, 192.168.x), and routable public IPs.
func looksLikeLocalIPv4(ip net.IP) bool {
	if ip == nil || len(ip) != 4 {
		return false
	}
	a := ip[0]
	// 0.0.0.0 = LISTEN all interfaces
	if a == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 {
		return true
	}
	// First octet ≤ 2: kernel bytes / alignment, not real IPs.
	if a <= 2 {
		return false
	}
	// Class E reserved (240+).
	if a >= 240 {
		return false
	}
	// Loopback (127.x.x.x) is valid for local bind.
	if a == 127 {
		return true
	}
	// Private ranges: allow even with zero octets (10.0.0.x, 192.168.0.x, etc.)
	if a == 10 {
		return true
	}
	if a == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	if a == 192 && ip[1] == 168 {
		return true
	}
	// Public IP: use the stricter check.
	return looksLikeIPv4(ip)
}

func looksLikeIPv4(ip net.IP) bool {
	if ip == nil || len(ip) != 4 {
		return false
	}
	a, b, c, d := ip[0], ip[1], ip[2], ip[3]
	// Any zero byte is likely padding, unconnected socket, or kernel data.
	if a == 0 || b == 0 || c == 0 || d == 0 {
		return false
	}
	// Reject IPs that are pool tag bytes (TcpE=54 63 70 45, UdpA=55 64 70 41…).
	if isPoolTagIP(ip) {
		return false
	}
	// First octet ≤ 2: kernel status codes / alignment.
	if a <= 2 {
		return false
	}
	// Loopback.
	if a == 127 {
		return false
	}
	// Class E reserved (240+).
	if a >= 240 {
		return false
	}
	// Link-local (169.254.x.x).
	if a == 169 && b == 254 {
		return false
	}
	// Public IPs: b≤1&&c≤1 is a telltale kernel pointer fragment.
	isPrivate := a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)
	if !isPrivate && b <= 1 && c <= 1 {
		return false
	}
	return true
}

// isPoolTagIP returns true when the 4 IP bytes spell out a known Windows
// network pool tag. This happens when the byte scanner finds a "TcpE"/"UdpA"
// sequence inside a data region (not a real pool header) and the surrounding
// memory happens to look like AF_INET + port + IP, with the pool tag itself
// landing in the IP field.
func isPoolTagIP(ip net.IP) bool {
	if len(ip) != 4 {
		return false
	}
	// TcpE=54 63 70 45, TcpL=54 63 70 4C: three-byte prefix 54 63 70
	if ip[0] == 0x54 && ip[1] == 0x63 && ip[2] == 0x70 {
		return true
	}
	// UdpA=55 64 70 41, UdpB=55 64 70 42, UdpC=55 64 70 43: prefix 55 64 70
	if ip[0] == 0x55 && ip[1] == 0x64 && ip[2] == 0x70 {
		return true
	}
	// Byte-shifted TcpE/TcpL: when the scanner finds AF_INET just before the pool
	// tag the IP field lands on bytes 1–3 of TcpE (63 70 45) or TcpL (63 70 4C).
	// Produces IPs like 99.112.69.x = 0x63 0x70 0x45 0x?? which are definite artifacts.
	if ip[0] == 0x63 && ip[1] == 0x70 && (ip[2] == 0x45 || ip[2] == 0x4C) {
		return true
	}
	// Byte-shifted UdpA/B/C: bytes 1–3 = 64 70 41/42/43
	if ip[0] == 0x64 && ip[1] == 0x70 && ip[2] >= 0x41 && ip[2] <= 0x43 {
		return true
	}
	return false
}

func isPort(p uint16) bool {
	// 0 and 65535 are not valid ports; powers-of-two > 0x1000 look like flags/sizes.
	if p == 0 || p == 0xFFFF {
		return false
	}
	// Ports 1-19 are all obsolete/unassigned on modern Windows; seeing them is a
	// strong signal of random pool bytes being misread as a port field.
	if p < 20 {
		return false
	}
	if p == 0x8000 || p == 0x4000 || p == 0x2000 {
		return false
	}
	// Port 512 (0x0200): big-endian encoding is [02][00], identical to the AF_INET
	// family marker. Seeing 02 00 02 00 in pool memory trivially produces a false
	// positive hit with port=512.
	// Port 5888 (0x1700): big-endian is [17][00], identical to AF_INET6 marker.
	if p == 0x0200 || p == 0x1700 {
		return false
	}
	// Port 257 (0x0101): big-endian bytes [01][01] — a repeating-byte pattern
	// common in zero-initialized or incrementing pool memory, not a real port.
	if p == 0x0101 {
		return false
	}
	return true
}

// looksLikeLocalIPv6 accepts only addresses that can unambiguously be a local
// IPv6 bind: :: (all-interfaces), ::1 (loopback), fe80::/10 (link-local),
// fc00::/7 or fd00::/8 (ULA private), and IPv4-mapped ::ffff:a.b.c.d.
// Global unicast and unknown prefixes are rejected — random pool bytes easily
// produce 16-byte patterns that pass generic non-zero checks, causing many
// false positives. The conservative accept-list approach is safer for pool scanning.
func looksLikeLocalIPv6(ip net.IP) bool {
	if len(ip) != 16 {
		return false
	}
	// :: = all zeros = LISTEN on all interfaces
	allZero := true
	for _, b := range ip {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return true
	}
	// ::1 = loopback
	if ip[15] == 1 {
		isLoopback := true
		for _, b := range ip[:15] {
			if b != 0 {
				isLoopback = false
				break
			}
		}
		if isLoopback {
			return true
		}
	}
	// fe80::/10 = link-local (auto-assigned on every IPv6 interface)
	if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}
	// fc00::/7 = Unique Local Address (fd00::/8 is the most common sub-range)
	if ip[0] == 0xfc || ip[0] == 0xfd {
		return true
	}
	// ::ffff:a.b.c.d = IPv4-mapped IPv6 address
	if ip[0] == 0 && ip[10] == 0xff && ip[11] == 0xff {
		mapped := net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
		return looksLikeLocalIPv4(mapped)
	}
	return false
}

func looksLikeIPv6(ip net.IP) bool {
	if len(ip) != 16 {
		return false
	}
	// Reject all-zeros (unbound) and all-ones (broadcast/multicast block).
	allZero, allFF := true, true
	for _, b := range ip {
		if b != 0x00 {
			allZero = false
		}
		if b != 0xFF {
			allFF = false
		}
	}
	if allZero || allFF {
		return false
	}
	// Reject multicast ff00::/8
	if ip[0] == 0xff {
		return false
	}
	// ::1 loopback
	if ip[15] == 1 {
		ok := true
		for _, b := range ip[:15] {
			if b != 0 {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	// fe80::/10 link-local
	if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}
	// fc00::/7 Unique Local Address
	if ip[0] == 0xfc || ip[0] == 0xfd {
		return true
	}
	// 2000::/3 global unicast (covers 2xxx and 3xxx addresses)
	if ip[0]&0xe0 == 0x20 {
		return true
	}
	// ::ffff:a.b.c.d IPv4-mapped — only if inner IPv4 passes strict check
	if ip[0] == 0 && ip[10] == 0xFF && ip[11] == 0xFF {
		mapped := net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
		return looksLikeIPv4(mapped)
	}
	// Unknown prefix — too risky to accept from pool scan
	return false
}

// formatHex is a small helper used by callers that want a hex string offset.
func formatHex(v uint64) string {
	return fmt.Sprintf("0x%X", v)
}
