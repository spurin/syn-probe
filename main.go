// syn-probe: half-open TCP SYN scanner using AF_PACKET.
//
// Replicates scapy's L3PacketSocket behaviour exactly:
// - AF_PACKET/SOCK_RAW/ETH_P_ALL for send+recv
// - Own ARP resolution via raw ARP request (not /proc/net/arp)
// - Filters PACKET_OUTGOING to ignore own transmitted frames
// - BPF filter on recv to only see IP packets from target
// - sendto with NULL sockaddr on bound socket
// - Socket buffer flush between ARP and SYN phases
//
// Requires root or CAP_NET_RAW.

package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const (
	ethPAll             = 0x0003
	ethPARP             = 0x0806
	ethPIP              = 0x0800
	solPacket           = 263
	packetAddMembership = 1
	packetAuxdata       = 8
	packetMrPromisc     = 1
	packetOutgoing      = 4
	soAttachFilter      = 26
	soDetachFilter      = 27
)

func main() {
	if len(os.Args) < 4 {
		usage()
	}
	cmd, host := os.Args[1], os.Args[2]
	port, _ := strconv.Atoi(os.Args[3])
	if port < 1 || port > 65535 {
		fatal("invalid port")
	}
	dstIP := resolveIP(host)

	switch cmd {
	case "syn":
		p := newProber(dstIP, port)
		defer p.close()
		if p.probeOnce(1 * time.Second) {
			fmt.Println("open")
			os.Exit(0)
		}
		fmt.Println("closed")
		os.Exit(1)
	case "wait":
		timeout, interval := 30.0, 0.3
		parseFlags(os.Args[4:], &timeout, &interval)
		p := newProber(dstIP, port)
		defer p.close()
		deadline := time.Now().Add(time.Duration(timeout * float64(time.Second)))
		attempt := 0
		for time.Now().Before(deadline) {
			attempt++
			if p.probeOnce(500 * time.Millisecond) {
				fmt.Printf("open after %d attempts\n", attempt)
				os.Exit(0)
			}
			time.Sleep(time.Duration(interval * float64(time.Second)))
		}
		fmt.Printf("timeout after %d attempts\n", attempt)
		os.Exit(1)
	default:
		usage()
	}
}

// ── prober ─────────────────────────────────────────────────────────

type prober struct {
	fd        int
	dstIP     net.IP
	dstPort   int
	srcIP     net.IP
	srcMAC    net.HardwareAddr
	dstMAC    net.HardwareAddr
	iface     *net.Interface
	arpDone   bool // true once we have a real (non-broadcast) MAC
	probeNum  int  // probe counter for periodic ARP retry
}

func newProber(dstIP net.IP, dstPort int) *prober {
	srcIP := localIP(dstIP)
	if srcIP == nil {
		fatal("no route to %s", dstIP)
	}
	iface := findIface(srcIP)
	if iface == nil {
		fatal("no interface for %s", srcIP)
	}

	// Flush stale ARP from kernel cache (VMs reuse IPs)
	exec.Command("ip", "neigh", "flush", "to", dstIP.String()).Run()

	// AF_PACKET, SOCK_RAW, ETH_P_ALL — like scapy's L3PacketSocket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		fatal("socket: %v — need root or CAP_NET_RAW", err)
	}

	// Promiscuous mode — like scapy
	mreq := struct {
		Ifindex int32
		Type    uint16
		Alen    uint16
		Addr    [8]byte
	}{Ifindex: int32(iface.Index), Type: packetMrPromisc}
	syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
		solPacket, packetAddMembership,
		uintptr(unsafe.Pointer(&mreq)), unsafe.Sizeof(mreq), 0)

	// Bind to interface — like scapy
	ll := syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  iface.Index,
	}
	syscall.Bind(fd, &ll)

	// PACKET_AUXDATA — like scapy
	syscall.SetsockoptInt(fd, solPacket, packetAuxdata, 1)

	// Flush buffered packets — like scapy's _flush_fd
	flushFd(fd)

	return &prober{fd: fd, dstIP: dstIP, dstPort: dstPort,
		srcIP: srcIP, srcMAC: iface.HardwareAddr, iface: iface}
}

func (p *prober) close() { syscall.Close(p.fd) }

// flushFd drains all buffered packets from the socket.
func flushFd(fd int) {
	buf := make([]byte, 65535)
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Usec: 1000})
	for {
		_, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			break
		}
	}
}

// broadcast MAC — used as fallback when ARP resolution fails.
// On a bridge network the frame still reaches the correct TAP port.
var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// probeOnce does one ARP resolve attempt + one SYN check.
// If ARP fails, uses broadcast MAC as fallback (like scapy does).
func (p *prober) probeOnce(timeout time.Duration) bool {
	p.probeNum++
	// Attempt ARP if we don't have a real MAC yet.
	// Retry ARP every 5 probes when using broadcast.
	if !p.arpDone && (p.dstMAC == nil || p.probeNum%5 == 0) {
		mac := p.arpResolve(500 * time.Millisecond)
		if mac != nil {
			p.dstMAC = mac
			p.arpDone = true
		} else if p.dstMAC == nil {
			// ARP failed — VM network stack may not be up yet.
			// Use broadcast MAC; the bridge will deliver the frame.
			p.dstMAC = broadcastMAC
		}
	}
	return p.synCheck(timeout)
}

// ── BPF filter ────────────────────────────────────────────────────
//
// Attach a BPF filter to only receive TCP packets from dstIP to our
// srcIP. This dramatically reduces the number of irrelevant packets
// the recv loop has to process — matching what scapy's sr1() does.

func (p *prober) attachSynFilter() {
	// BPF program: match Ethernet IP frames (0x0800) containing TCP (proto 6)
	// from p.dstIP to p.srcIP.
	//
	// Equivalent tcpdump filter:
	//   ether proto 0x0800 and ip proto 6 and src host <dstIP> and dst host <srcIP>
	dstIPu32 := binary.BigEndian.Uint32(p.dstIP.To4())
	srcIPu32 := binary.BigEndian.Uint32(p.srcIP.To4())

	filter := []bpfInsn{
		// [0] Load EtherType (offset 12, 2 bytes)
		{0x28, 0, 0, 12},
		// [1] Jump if != 0x0800 → reject
		{0x15, 0, 7, ethPIP},
		// [2] Load IP protocol (offset 14+9 = 23, 1 byte)
		{0x30, 0, 0, 23},
		// [3] Jump if != TCP(6) → reject
		{0x15, 0, 5, 6},
		// [4] Load src IP (offset 14+12 = 26, 4 bytes)
		{0x20, 0, 0, 26},
		// [5] Jump if != dstIP → reject (src IP in packet = our dstIP)
		{0x15, 0, 3, uint32(dstIPu32)},
		// [6] Load dst IP (offset 14+16 = 30, 4 bytes)
		{0x20, 0, 0, 30},
		// [7] Jump if != srcIP → reject (dst IP in packet = our srcIP)
		{0x15, 0, 1, uint32(srcIPu32)},
		// [8] Accept: return 65535
		{0x06, 0, 0, 65535},
		// [9] Reject: return 0
		{0x06, 0, 0, 0},
	}
	p.setBPF(filter)
}

func (p *prober) attachARPFilter() {
	// BPF: match ARP replies (0x0806, op=2) from dstIP
	dstIPu32 := binary.BigEndian.Uint32(p.dstIP.To4())

	filter := []bpfInsn{
		// [0] Load EtherType
		{0x28, 0, 0, 12},
		// [1] Jump if != ARP → reject
		{0x15, 0, 5, ethPARP},
		// [2] Load ARP opcode (offset 14+6 = 20, 2 bytes)
		{0x28, 0, 0, 20},
		// [3] Jump if != 2 (reply) → reject
		{0x15, 0, 3, 2},
		// [4] Load ARP sender IP (offset 14+14 = 28, 4 bytes)
		{0x20, 0, 0, 28},
		// [5] Jump if != dstIP → reject
		{0x15, 0, 1, uint32(dstIPu32)},
		// [6] Accept
		{0x06, 0, 0, 65535},
		// [7] Reject
		{0x06, 0, 0, 0},
	}
	p.setBPF(filter)
}

func (p *prober) detachBPF() {
	syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(p.fd), syscall.SOL_SOCKET, soDetachFilter,
		0, 0, 0)
}

type bpfInsn struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

func (p *prober) setBPF(insns []bpfInsn) {
	prog := struct {
		Len    uint16
		_      [6]byte // padding
		Filter *bpfInsn
	}{
		Len:    uint16(len(insns)),
		Filter: &insns[0],
	}
	syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(p.fd), syscall.SOL_SOCKET, soAttachFilter,
		uintptr(unsafe.Pointer(&prog)), unsafe.Sizeof(prog), 0)
}

// ── ARP resolution (like scapy's getmacbyip → srp1) ───────────────

func (p *prober) arpResolve(timeout time.Duration) net.HardwareAddr {
	// Attach ARP-only BPF filter
	p.attachARPFilter()
	defer p.detachBPF()

	// Flush any buffered packets before ARP
	flushFd(p.fd)

	// Build ARP request: Ether(dst=broadcast) / ARP(op=1, pdst=dstIP)
	arp := make([]byte, 42)
	// Ethernet header
	copy(arp[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // broadcast
	copy(arp[6:12], p.srcMAC)
	binary.BigEndian.PutUint16(arp[12:14], ethPARP)
	// ARP payload
	binary.BigEndian.PutUint16(arp[14:16], 1)      // hw type: Ethernet
	binary.BigEndian.PutUint16(arp[16:18], ethPIP)  // proto: IPv4
	arp[18] = 6                                     // hw addr len
	arp[19] = 4                                     // proto addr len
	binary.BigEndian.PutUint16(arp[20:22], 1)       // op: request
	copy(arp[22:28], p.srcMAC)                      // sender hw
	copy(arp[28:32], p.srcIP.To4())                 // sender IP
	// target hw: 00:00:00:00:00:00 (bytes 32-37, already zero)
	copy(arp[38:42], p.dstIP.To4())                 // target IP

	// Send ARP request on our ETH_P_ALL socket
	sendRaw(p.fd, arp)

	// Set timeout and listen for ARP reply
	tv := syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int64((timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(p.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	buf := make([]byte, 65535)
	dl := time.Now().Add(timeout)
	for time.Now().Before(dl) {
		n, from, err := syscall.Recvfrom(p.fd, buf, 0)
		if err != nil {
			return nil
		}
		// Skip outgoing packets (like scapy)
		if ll, ok := from.(*syscall.SockaddrLinklayer); ok && ll.Pkttype == packetOutgoing {
			continue
		}
		if n < 42 {
			continue
		}
		// BPF should have filtered, but double-check
		if binary.BigEndian.Uint16(buf[12:14]) != ethPARP {
			continue
		}
		if binary.BigEndian.Uint16(buf[20:22]) != 2 {
			continue // not a reply
		}
		senderIP := net.IP(buf[28:32])
		if !senderIP.Equal(p.dstIP) {
			continue
		}
		// Got it — extract sender MAC
		mac := make(net.HardwareAddr, 6)
		copy(mac, buf[22:28])
		return mac
	}
	return nil
}

// ── SYN check ──────────────────────────────────────────────────────

func (p *prober) synCheck(timeout time.Duration) bool {
	srcPort := 40000 + rand.Intn(20000)
	seq := rand.Uint32()

	// Attach TCP-from-target BPF filter
	p.attachSynFilter()
	defer p.detachBPF()

	// Flush socket buffer before SYN — critical to avoid processing
	// stale packets from prior ARP or SYN attempts
	flushFd(p.fd)

	// Build Ethernet + IP + TCP SYN
	tcp := buildTCP(p.srcIP, p.dstIP, srcPort, p.dstPort, seq, 0, 0x02)
	ip := buildIP(p.srcIP, p.dstIP, tcp)
	frame := buildEth(p.srcMAC, p.dstMAC, ethPIP, ip)

	// Send with NULL sockaddr (like scapy)
	sendRaw(p.fd, frame)

	// Set timeout
	tv := syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int64((timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(p.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Receive looking for SYN-ACK — BPF filter means we only see TCP from target
	buf := make([]byte, 65535)
	dl := time.Now().Add(timeout)
	for time.Now().Before(dl) {
		n, from, err := syscall.Recvfrom(p.fd, buf, 0)
		if err != nil {
			return false
		}
		// Skip outgoing (like scapy)
		if ll, ok := from.(*syscall.SockaddrLinklayer); ok && ll.Pkttype == packetOutgoing {
			continue
		}
		if n < 54 {
			continue
		}
		if binary.BigEndian.Uint16(buf[12:14]) != ethPIP {
			continue
		}
		ipH := buf[14:]
		if ipH[0]>>4 != 4 || ipH[9] != 6 {
			continue
		}
		ihl := int(ipH[0]&0x0F) * 4
		if !net.IP(ipH[12:16]).Equal(p.dstIP) {
			continue
		}
		tcpH := ipH[ihl:]
		if len(tcpH) < 14 {
			continue
		}
		if int(binary.BigEndian.Uint16(tcpH[0:2])) != p.dstPort ||
			int(binary.BigEndian.Uint16(tcpH[2:4])) != srcPort {
			continue
		}
		flags := tcpH[13]
		if flags&0x12 == 0x12 { // SYN+ACK
			ack := binary.BigEndian.Uint32(tcpH[8:12])
			rstTcp := buildTCP(p.srcIP, p.dstIP, srcPort, p.dstPort, seq+1, ack, 0x14)
			rstIp := buildIP(p.srcIP, p.dstIP, rstTcp)
			rstFrame := buildEth(p.srcMAC, p.dstMAC, ethPIP, rstIp)
			sendRaw(p.fd, rstFrame)
			return true
		}
		if flags&0x04 != 0 {
			return false
		}
	}
	return false
}

// ── packet helpers ─────────────────────────────────────────────────

func sendRaw(fd int, buf []byte) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_SENDTO,
		uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func buildEth(src, dst net.HardwareAddr, proto uint16, payload []byte) []byte {
	f := make([]byte, 14+len(payload))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:14], proto)
	copy(f[14:], payload)
	return f
}

func buildIP(src, dst net.IP, payload []byte) []byte {
	tl := 20 + len(payload)
	p := make([]byte, tl)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(tl))
	binary.BigEndian.PutUint16(p[4:6], uint16(rand.Intn(65535)))
	p[8] = 64
	p[9] = 6
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	copy(p[20:], payload)
	binary.BigEndian.PutUint16(p[10:12], csum(p[:20]))
	return p
}

func buildTCP(src, dst net.IP, sp, dp int, seq, ack uint32, flags byte) []byte {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:2], uint16(sp))
	binary.BigEndian.PutUint16(t[2:4], uint16(dp))
	binary.BigEndian.PutUint32(t[4:8], seq)
	binary.BigEndian.PutUint32(t[8:12], ack)
	t[12] = 5 << 4
	t[13] = flags
	binary.BigEndian.PutUint16(t[14:16], 64240)
	ph := make([]byte, 32)
	copy(ph[0:4], src.To4())
	copy(ph[4:8], dst.To4())
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:12], 20)
	copy(ph[12:], t)
	binary.BigEndian.PutUint16(t[16:18], csum(ph))
	return t
}

func csum(d []byte) uint16 {
	var s uint32
	for i := 0; i < len(d)-1; i += 2 {
		s += uint32(binary.BigEndian.Uint16(d[i : i+2]))
	}
	if len(d)%2 == 1 {
		s += uint32(d[len(d)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return ^uint16(s)
}

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

// ── helpers ────────────────────────────────────────────────────────

func localIP(dst net.IP) net.IP {
	c, _ := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dst, Port: 1})
	if c == nil {
		return nil
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.To4()
}

func findIface(ip net.IP) *net.Interface {
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		addrs, _ := ifaces[i].Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.To4().Equal(ip) {
				return &ifaces[i]
			}
		}
	}
	return nil
}

func resolveIP(h string) net.IP {
	if ip := net.ParseIP(h); ip != nil {
		return ip.To4()
	}
	a, _ := net.LookupHost(h)
	if len(a) > 0 {
		return net.ParseIP(a[0]).To4()
	}
	fatal("cannot resolve: %s", h)
	return nil
}

func parseFlags(args []string, t, i *float64) {
	for j := 0; j < len(args)-1; j++ {
		switch args[j] {
		case "--timeout":
			j++
			if v, e := strconv.ParseFloat(args[j], 64); e == nil {
				*t = v
			}
		case "--interval":
			j++
			if v, e := strconv.ParseFloat(args[j], 64); e == nil {
				*i = v
			}
		}
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: syn-probe {syn|wait} <host> <port> [--timeout S] [--interval S]\n")
	os.Exit(2)
}

func fatal(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "syn-probe: "+f+"\n", a...)
	os.Exit(2)
}

// suppress unused import warning
var _ = exec.Command
