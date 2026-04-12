package client

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blackestwhite/iqs-tunnel/internal/config"
	"github.com/blackestwhite/iqs-tunnel/internal/dnsmsg"
	"github.com/blackestwhite/iqs-tunnel/internal/protocol"
)

type sentPacket struct {
	packet   protocol.Packet
	lastSent time.Time
	attempts int
}

type resolverState struct {
	addr          *net.UDPAddr
	ewmaRTT       time.Duration
	failures      float64
	cooldownUntil time.Time
}

type Client struct {
	cfg    config.Client
	secret []byte

	sessionID uint64
	localConn *net.UDPConn
	wanConn   *net.UDPConn

	resolverMu sync.Mutex
	resolvers  []*resolverState
	domainRR   uint32

	uplinkSeq uint32

	sendQueue chan uint32

	sentMu      sync.Mutex
	sentPackets map[uint32]*sentPacket

	lastLocalMu   sync.RWMutex
	lastLocalAddr *net.UDPAddr

	downRecv *protocol.ReceiverWindow
	downAsm  *protocol.Reassembler

	ackDirty atomic.Bool

	publicIPMu sync.RWMutex
	publicIP   net.IP

	lastDownlink atomic.Int64
}

func Run(ctx context.Context, cfg config.Client) error {
	client, err := newClient(cfg)
	if err != nil {
		return err
	}
	return client.run(ctx)
}

func newClient(cfg config.Client) (*Client, error) {
	localAddr, err := net.ResolveUDPAddr("udp4", cfg.LocalBind)
	if err != nil {
		return nil, fmt.Errorf("resolve local_bind: %w", err)
	}
	localConn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil, fmt.Errorf("listen local_bind: %w", err)
	}

	wanAddr, err := net.ResolveUDPAddr("udp4", cfg.WANBind)
	if err != nil {
		_ = localConn.Close()
		return nil, fmt.Errorf("resolve wan_bind: %w", err)
	}
	wanConn, err := net.ListenUDP("udp4", wanAddr)
	if err != nil {
		_ = localConn.Close()
		return nil, fmt.Errorf("listen wan_bind: %w", err)
	}

	resolvers := make([]*resolverState, 0, len(cfg.Resolvers))
	for _, raw := range cfg.Resolvers {
		addr, err := net.ResolveUDPAddr("udp4", normalizeResolver(raw))
		if err != nil {
			_ = wanConn.Close()
			_ = localConn.Close()
			return nil, fmt.Errorf("resolve resolver %q: %w", raw, err)
		}
		resolvers = append(resolvers, &resolverState{addr: addr})
	}

	sessionID := cfg.SessionID
	if sessionID == 0 {
		sessionID = randUint64()
	}

	client := &Client{
		cfg:         cfg,
		secret:      []byte(cfg.Secret),
		sessionID:   sessionID,
		localConn:   localConn,
		wanConn:     wanConn,
		resolvers:   resolvers,
		sendQueue:   make(chan uint32, cfg.QueueSize),
		sentPackets: make(map[uint32]*sentPacket),
		downRecv:    protocol.NewReceiverWindow(),
		downAsm:     protocol.NewReassembler(15 * time.Second),
	}
	client.lastDownlink.Store(time.Now().UnixNano())
	return client, nil
}

func (c *Client) run(ctx context.Context) error {
	defer c.localConn.Close()
	defer c.wanConn.Close()

	ip, err := c.resolvePublicIP(ctx)
	if err != nil {
		return err
	}
	c.publicIPMu.Lock()
	c.publicIP = ip
	c.publicIPMu.Unlock()

	if err := c.queueInfoPacket(); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	start := func(fn func(context.Context) error) {
		go func() {
			if err := fn(ctx); err != nil && ctx.Err() == nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}()
	}

	start(c.localIngressLoop)
	start(c.spoofReceiveLoop)
	start(c.sendLoop)
	start(c.retransmitLoop)
	start(c.ackFlushLoop)
	start(c.keepaliveLoop)
	start(c.infoRefreshLoop)

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (c *Client) localIngressLoop(ctx context.Context) error {
	buf := make([]byte, 64*1024)
	for {
		_ = c.localConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := c.localConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			return fmt.Errorf("read local udp: %w", err)
		}
		if n == 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		c.lastLocalMu.Lock()
		c.lastLocalAddr = addr
		c.lastLocalMu.Unlock()
		if err := c.queuePacket(protocol.TypeData, payload); err != nil {
			return err
		}
	}
}

func (c *Client) spoofReceiveLoop(ctx context.Context) error {
	buf := make([]byte, 64*1024)
	for {
		_ = c.wanConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := c.wanConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			return fmt.Errorf("read spoof udp: %w", err)
		}
		if n == 0 {
			continue
		}
		fragment, err := protocol.UnmarshalFragment(buf[:n])
		if err != nil {
			continue
		}
		packetRaw, done, err := c.downAsm.Add(fragment)
		if err != nil || !done {
			continue
		}
		packet, err := protocol.UnmarshalPacket(packetRaw, c.secret)
		if err != nil {
			continue
		}
		if packet.SessionID != c.sessionID {
			continue
		}
		if !c.downRecv.MarkReceived(packet.Seq) {
			continue
		}
		c.ackDirty.Store(true)
		c.lastDownlink.Store(time.Now().UnixNano())
		if packet.Type != protocol.TypeData || len(packet.Payload) == 0 {
			continue
		}
		c.lastLocalMu.RLock()
		addr := c.lastLocalAddr
		c.lastLocalMu.RUnlock()
		if addr == nil {
			continue
		}
		if _, err := c.localConn.WriteToUDP(packet.Payload, addr); err != nil {
			log.Printf("forward downlink to local app: %v", err)
		}
	}
}

func (c *Client) sendLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case seq := <-c.sendQueue:
			if err := c.sendSequence(ctx, seq); err != nil {
				log.Printf("send sequence %d: %v", seq, err)
			}
		}
	}
}

func (c *Client) sendSequence(ctx context.Context, seq uint32) error {
	c.sentMu.Lock()
	sp, ok := c.sentPackets[seq]
	if !ok {
		c.sentMu.Unlock()
		return nil
	}
	packet := sp.packet
	c.sentMu.Unlock()

	ack := c.downRecv.Snapshot()
	packet.Ack = ack.Ack
	packet.AckBits = ack.Bits

	packetRaw, err := packet.Marshal(c.secret)
	if err != nil {
		return err
	}
	domain := c.pickDomain()
	maxPayload := c.cfg.DNSPayloadBytes
	if maxPayload == 0 {
		maxPayload = protocol.MaxDNSRawFragmentPayload(domain, c.cfg.MaxQNameLen, c.cfg.MaxLabelLen)
		if maxPayload == 0 {
			return fmt.Errorf("unable to compute DNS fragment size for %s", domain)
		}
	}
	fragments, err := protocol.FragmentPacket(packetRaw, c.sessionID, packet.Seq, maxPayload, 0, randUint32())
	if err != nil {
		return err
	}
	for _, fragment := range fragments {
		rawFragment, err := fragment.MarshalBinary()
		if err != nil {
			return err
		}
		qname := protocol.EncodeDNSName(rawFragment, domain, c.cfg.MaxLabelLen)
		if len(qname) > c.cfg.MaxQNameLen {
			return fmt.Errorf("qname too long (%d) for %s", len(qname), domain)
		}
		report, err := c.queryTXT(ctx, qname)
		if err != nil {
			return err
		}
		c.applyServerAck(report)
	}

	c.sentMu.Lock()
	if current, ok := c.sentPackets[seq]; ok {
		current.lastSent = time.Now()
		current.attempts++
	}
	c.sentMu.Unlock()
	return nil
}

func (c *Client) retransmitLoop(ctx context.Context) error {
	ticker := time.NewTicker(time.Duration(c.cfg.RetransmitMS) * time.Millisecond / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := time.Now()
			c.sentMu.Lock()
			for seq, packet := range c.sentPackets {
				if packet.lastSent.IsZero() || now.Sub(packet.lastSent) >= time.Duration(c.cfg.RetransmitMS)*time.Millisecond {
					select {
					case c.sendQueue <- seq:
					default:
					}
				}
			}
			c.sentMu.Unlock()
		}
	}
}

func (c *Client) ackFlushLoop(ctx context.Context) error {
	ticker := time.NewTicker(time.Duration(c.cfg.AckFlushMS) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if !c.ackDirty.Swap(false) {
				continue
			}
			if err := c.queuePacket(protocol.TypeAckOnly, nil); err != nil {
				return err
			}
		}
	}
}

func (c *Client) keepaliveLoop(ctx context.Context) error {
	fast := time.Duration(c.cfg.KeepaliveFastMS) * time.Millisecond
	slow := time.Duration(c.cfg.KeepaliveSlowMS) * time.Millisecond
	if slow < fast {
		slow = fast
	}
	timer := time.NewTimer(fast)
	defer timer.Stop()
	dst := &net.UDPAddr{IP: net.ParseIP(c.cfg.FakeSendIP).To4(), Port: c.cfg.FakeSendPort}
	if dst.IP == nil {
		return fmt.Errorf("invalid fake_send_ip %q", c.cfg.FakeSendIP)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			payload := make([]byte, 280)
			fillRandom(payload)
			if _, err := c.wanConn.WriteToUDP(payload, dst); err != nil {
				log.Printf("nat keepalive: %v", err)
			}
			last := time.Unix(0, c.lastDownlink.Load())
			next := slow
			if time.Since(last) > 30*time.Second {
				next = fast
			}
			timer.Reset(next)
		}
	}
}

func (c *Client) infoRefreshLoop(ctx context.Context) error {
	ticker := time.NewTicker(time.Duration(c.cfg.InfoRefreshMS) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			ip, err := c.resolvePublicIP(ctx)
			if err != nil {
				log.Printf("refresh public ip: %v", err)
				continue
			}
			c.publicIPMu.Lock()
			c.publicIP = ip
			c.publicIPMu.Unlock()
			if err := c.queueInfoPacket(); err != nil {
				return err
			}
		}
	}
}

func (c *Client) queueInfoPacket() error {
	publicIP := c.currentPublicIP()
	if publicIP == nil {
		return fmt.Errorf("public IP is not available")
	}
	wanAddr := c.wanConn.LocalAddr().(*net.UDPAddr)
	var info protocol.InfoPayload
	copy(info.ClientIP[:], publicIP.To4())
	info.ClientPort = uint16(wanAddr.Port)
	spoofIP := net.ParseIP(c.cfg.FakeSendIP).To4()
	if spoofIP == nil {
		return fmt.Errorf("invalid fake_send_ip %q", c.cfg.FakeSendIP)
	}
	copy(info.SpoofIP[:], spoofIP)
	info.SpoofPort = uint16(c.cfg.FakeSendPort)
	return c.queuePacket(protocol.TypeInfo, info.MarshalBinary())
}

func (c *Client) queuePacket(packetType uint8, payload []byte) error {
	ack := c.downRecv.Snapshot()
	seq := atomic.AddUint32(&c.uplinkSeq, 1)
	packet := protocol.Packet{
		Type:      packetType,
		SessionID: c.sessionID,
		Seq:       seq,
		Ack:       ack.Ack,
		AckBits:   ack.Bits,
		Payload:   payload,
	}
	c.sentMu.Lock()
	c.sentPackets[seq] = &sentPacket{packet: packet}
	c.sentMu.Unlock()
	select {
	case c.sendQueue <- seq:
		return nil
	default:
		return fmt.Errorf("send queue is full")
	}
}

func (c *Client) queryTXT(ctx context.Context, qname string) (protocol.AckReport, error) {
	resolver := c.pickResolver()
	if resolver == nil {
		return protocol.AckReport{}, fmt.Errorf("no resolver available")
	}
	conn, err := net.DialUDP("udp4", nil, resolver.addr)
	if err != nil {
		c.recordResolverFailure(resolver)
		return protocol.AckReport{}, err
	}
	defer conn.Close()

	queryID := uint16(randUint32())
	query, err := dnsmsg.BuildTXTQuery(queryID, qname)
	if err != nil {
		return protocol.AckReport{}, err
	}

	start := time.Now()
	if err := conn.SetDeadline(time.Now().Add(time.Duration(c.cfg.QueryTimeoutMS) * time.Millisecond)); err != nil {
		return protocol.AckReport{}, err
	}
	if _, err := conn.Write(query); err != nil {
		c.recordResolverFailure(resolver)
		return protocol.AckReport{}, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		c.recordResolverFailure(resolver)
		return protocol.AckReport{}, err
	}
	id, txts, err := dnsmsg.ParseTXTResponse(buf[:n])
	if err != nil {
		c.recordResolverFailure(resolver)
		return protocol.AckReport{}, err
	}
	if id != queryID {
		c.recordResolverFailure(resolver)
		return protocol.AckReport{}, fmt.Errorf("dns id mismatch")
	}
	if len(txts) == 0 {
		c.recordResolverFailure(resolver)
		return protocol.AckReport{}, fmt.Errorf("dns response did not contain a TXT ack")
	}
	rawReport, err := protocol.DecodeBase32NoPad(txts[0])
	if err != nil {
		c.recordResolverFailure(resolver)
		return protocol.AckReport{}, err
	}
	report, err := protocol.UnmarshalAckReport(rawReport, c.secret)
	if err != nil {
		c.recordResolverFailure(resolver)
		return protocol.AckReport{}, err
	}
	c.recordResolverSuccess(resolver, time.Since(start))
	return report, nil
}

func (c *Client) applyServerAck(report protocol.AckReport) {
	if report.SessionID != c.sessionID {
		return
	}
	ack := protocol.AckState{Ack: report.Ack, Bits: report.AckBits}
	c.sentMu.Lock()
	defer c.sentMu.Unlock()
	for seq := range c.sentPackets {
		if ack.Acks(seq) {
			delete(c.sentPackets, seq)
		}
	}
}

func (c *Client) pickDomain() string {
	idx := atomic.AddUint32(&c.domainRR, 1)
	return c.cfg.Domains[int(idx-1)%len(c.cfg.Domains)]
}

func (c *Client) pickResolver() *resolverState {
	c.resolverMu.Lock()
	defer c.resolverMu.Unlock()

	now := time.Now()
	var best *resolverState
	bestScore := 1e18
	for _, resolver := range c.resolvers {
		score := c.resolverScore(resolver, now)
		if score < bestScore {
			best = resolver
			bestScore = score
		}
	}
	return best
}

func (c *Client) resolverScore(resolver *resolverState, now time.Time) float64 {
	score := float64(resolver.ewmaRTT.Milliseconds())
	if score == 0 {
		score = 40
	}
	score += resolver.failures * c.cfg.ResolverFailureWeight
	if resolver.cooldownUntil.After(now) {
		score += 100000
	}
	return score
}

func (c *Client) recordResolverSuccess(resolver *resolverState, rtt time.Duration) {
	c.resolverMu.Lock()
	defer c.resolverMu.Unlock()
	if resolver.ewmaRTT == 0 {
		resolver.ewmaRTT = rtt
	} else {
		resolver.ewmaRTT = (resolver.ewmaRTT*4 + rtt) / 5
	}
	resolver.failures *= 0.6
	resolver.cooldownUntil = time.Time{}
}

func (c *Client) recordResolverFailure(resolver *resolverState) {
	c.resolverMu.Lock()
	defer c.resolverMu.Unlock()
	resolver.failures++
	resolver.cooldownUntil = time.Now().Add(time.Duration(c.cfg.ResolverCooldownMS) * time.Millisecond)
}

func (c *Client) resolvePublicIP(ctx context.Context) (net.IP, error) {
	if c.cfg.PublicIP != "" {
		ip := net.ParseIP(c.cfg.PublicIP).To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid public_ip %q", c.cfg.PublicIP)
		}
		return ip, nil
	}
	if strings.TrimSpace(c.cfg.PublicIPURL) == "" {
		return nil, fmt.Errorf("either public_ip or public_ip_url is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.PublicIPURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	match := re.Find(body)
	if len(match) == 0 {
		return nil, fmt.Errorf("no IPv4 address found in public IP response")
	}
	ip := net.ParseIP(string(match)).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid public IP %q", string(match))
	}
	return ip, nil
}

func (c *Client) currentPublicIP() net.IP {
	c.publicIPMu.RLock()
	defer c.publicIPMu.RUnlock()
	if c.publicIP == nil {
		return nil
	}
	ip := make(net.IP, len(c.publicIP))
	copy(ip, c.publicIP)
	return ip
}

func normalizeResolver(raw string) string {
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw
	}
	return net.JoinHostPort(raw, "53")
}

func randUint32() uint32 {
	var raw [4]byte
	fillRandom(raw[:])
	return binary.BigEndian.Uint32(raw[:])
}

func randUint64() uint64 {
	var raw [8]byte
	fillRandom(raw[:])
	return binary.BigEndian.Uint64(raw[:])
}

func fillRandom(dst []byte) {
	if _, err := io.ReadFull(crand.Reader, dst); err != nil {
		panic(err)
	}
}
