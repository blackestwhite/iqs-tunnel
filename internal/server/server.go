package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/blackestwhite/iqs-tunnel/internal/config"
	"github.com/blackestwhite/iqs-tunnel/internal/dnsmsg"
	"github.com/blackestwhite/iqs-tunnel/internal/protocol"
	"github.com/blackestwhite/iqs-tunnel/internal/rawip"
)

type downPacket struct {
	packet   protocol.Packet
	lastSent time.Time
	attempts int
}

type session struct {
	id uint64

	server *Server

	mu sync.Mutex

	info    protocol.InfoPayload
	hasInfo bool

	uplinkRecv *protocol.ReceiverWindow
	uplinkAsm  *protocol.Reassembler

	upstreamConn *net.UDPConn

	nextDownSeq uint32
	downSent    map[uint32]*downPacket

	lastSeen time.Time
}

type Server struct {
	cfg       config.Server
	secret    []byte
	dnsConn   *net.UDPConn
	rawSender *rawip.Sender

	upstreamAddr *net.UDPAddr

	sessionsMu sync.RWMutex
	sessions   map[uint64]*session
}

func Run(ctx context.Context, cfg config.Server) error {
	server, err := newServer(cfg)
	if err != nil {
		return err
	}
	return server.run(ctx)
}

func newServer(cfg config.Server) (*Server, error) {
	listenAddr, err := net.ResolveUDPAddr("udp4", cfg.ListenDNS)
	if err != nil {
		return nil, fmt.Errorf("resolve listen_dns: %w", err)
	}
	dnsConn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen dns: %w", err)
	}
	upstreamAddr, err := net.ResolveUDPAddr("udp4", cfg.UpstreamAddress)
	if err != nil {
		_ = dnsConn.Close()
		return nil, fmt.Errorf("resolve upstream_address: %w", err)
	}
	rawSender, err := rawip.NewSender()
	if err != nil {
		_ = dnsConn.Close()
		return nil, fmt.Errorf("open raw sender: %w", err)
	}
	return &Server{
		cfg:          cfg,
		secret:       []byte(cfg.Secret),
		dnsConn:      dnsConn,
		rawSender:    rawSender,
		upstreamAddr: upstreamAddr,
		sessions:     make(map[uint64]*session),
	}, nil
}

func (s *Server) run(ctx context.Context) error {
	defer s.dnsConn.Close()
	defer s.rawSender.Close()

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

	start(s.dnsLoop)
	start(s.retransmitLoop)
	start(s.cleanupLoop)

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) dnsLoop(ctx context.Context) error {
	buf := make([]byte, 64*1024)
	for {
		_ = s.dnsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := s.dnsConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			return fmt.Errorf("read dns: %w", err)
		}
		if n == 0 {
			continue
		}
		if err := s.handleDNSPacket(ctx, addr, buf[:n]); err != nil {
			log.Printf("dns packet from %v: %v", addr, err)
		}
	}
}

func (s *Server) handleDNSPacket(ctx context.Context, addr *net.UDPAddr, packet []byte) error {
	question, err := dnsmsg.ParseQuestion(packet)
	if err != nil {
		return err
	}
	matchedDomain, ok := s.matchDomain(question.Name)
	if !ok {
		return fmt.Errorf("unrecognized qname %q", question.Name)
	}
	rawFragment, err := protocol.DecodeDNSName(question.Name, matchedDomain)
	if err != nil {
		return err
	}
	fragment, err := protocol.UnmarshalFragment(rawFragment)
	if err != nil {
		return err
	}

	session := s.getSession(fragment.SessionID)
	session.touch()

	packetRaw, done, err := session.uplinkAsm.Add(fragment)
	if err != nil {
		return err
	}
	if done {
		tunnelPacket, err := protocol.UnmarshalPacket(packetRaw, s.secret)
		if err != nil {
			return err
		}
		if tunnelPacket.SessionID != session.id {
			return fmt.Errorf("session mismatch for packet %d", tunnelPacket.Seq)
		}
		session.handlePeerAck(protocol.AckState{Ack: tunnelPacket.Ack, Bits: tunnelPacket.AckBits})
		if tunnelPacket.Type == protocol.TypeInfo {
			info, err := protocol.ParseInfoPayload(tunnelPacket.Payload)
			if err != nil {
				return err
			}
			if err := session.updateInfo(ctx, info); err != nil {
				return err
			}
		}
		if isNew := session.uplinkRecv.MarkReceived(tunnelPacket.Seq); isNew {
			switch tunnelPacket.Type {
			case protocol.TypeData:
				if err := session.forwardUpstream(tunnelPacket.Payload); err != nil {
					return err
				}
			case protocol.TypeAckOnly, protocol.TypeKeepalive, protocol.TypeInfo:
			default:
				return fmt.Errorf("unsupported packet type %d", tunnelPacket.Type)
			}
		}
	}

	ack := session.uplinkRecv.Snapshot()
	response, err := dnsmsg.BuildTXTResponse(question, protocol.EncodeBase32NoPad((protocol.AckReport{
		SessionID: session.id,
		Ack:       ack.Ack,
		AckBits:   ack.Bits,
	}).Marshal(s.secret)))
	if err != nil {
		return err
	}
	_, err = s.dnsConn.WriteToUDP(response, addr)
	return err
}

func (s *Server) retransmitLoop(ctx context.Context) error {
	ticker := time.NewTicker(time.Duration(s.cfg.DownlinkRetransmitMS) * time.Millisecond / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := time.Now()
			s.sessionsMu.RLock()
			sessions := make([]*session, 0, len(s.sessions))
			for _, session := range s.sessions {
				sessions = append(sessions, session)
			}
			s.sessionsMu.RUnlock()
			for _, session := range sessions {
				session.mu.Lock()
				var resend []*downPacket
				for _, packet := range session.downSent {
					if packet.lastSent.IsZero() || now.Sub(packet.lastSent) >= time.Duration(s.cfg.DownlinkRetransmitMS)*time.Millisecond {
						resend = append(resend, packet)
					}
				}
				session.mu.Unlock()
				for _, packet := range resend {
					if err := session.sendDownPacket(packet); err != nil {
						log.Printf("resend session %d seq %d: %v", session.id, packet.packet.Seq, err)
					}
				}
			}
		}
	}
}

func (s *Server) cleanupLoop(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	timeout := time.Duration(s.cfg.SessionTimeoutMS) * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := time.Now()
			var stale []*session
			s.sessionsMu.Lock()
			for id, session := range s.sessions {
				session.mu.Lock()
				expired := now.Sub(session.lastSeen) > timeout
				session.mu.Unlock()
				if expired {
					stale = append(stale, session)
					delete(s.sessions, id)
				}
			}
			s.sessionsMu.Unlock()
			for _, session := range stale {
				session.close()
			}
		}
	}
}

func (s *Server) matchDomain(qname string) (string, bool) {
	qname = strings.Trim(strings.ToLower(qname), ".")
	for _, domain := range s.cfg.Domains {
		domain = strings.Trim(strings.ToLower(domain), ".")
		if qname == domain || strings.HasSuffix(qname, "."+domain) {
			return domain, true
		}
	}
	return "", false
}

func (s *Server) getSession(id uint64) *session {
	s.sessionsMu.RLock()
	if existing, ok := s.sessions[id]; ok {
		s.sessionsMu.RUnlock()
		return existing
	}
	s.sessionsMu.RUnlock()

	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if existing, ok := s.sessions[id]; ok {
		return existing
	}
	session := &session{
		id:         id,
		server:     s,
		uplinkRecv: protocol.NewReceiverWindow(),
		uplinkAsm:  protocol.NewReassembler(15 * time.Second),
		downSent:   make(map[uint32]*downPacket),
		lastSeen:   time.Now(),
	}
	s.sessions[id] = session
	return session
}

func (sess *session) touch() {
	sess.mu.Lock()
	sess.lastSeen = time.Now()
	sess.mu.Unlock()
}

func (sess *session) close() {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.upstreamConn != nil {
		_ = sess.upstreamConn.Close()
		sess.upstreamConn = nil
	}
}

func (sess *session) updateInfo(ctx context.Context, info protocol.InfoPayload) error {
	sess.mu.Lock()
	sess.info = info
	sess.hasInfo = true
	needsUpstream := sess.upstreamConn == nil
	sess.lastSeen = time.Now()
	sess.mu.Unlock()

	if !needsUpstream {
		return nil
	}
	conn, err := net.DialUDP("udp4", nil, sess.server.upstreamAddr)
	if err != nil {
		return err
	}
	if err := conn.SetReadBuffer(sess.server.cfg.UpstreamReadBufferSize); err != nil {
		_ = conn.Close()
		return err
	}
	sess.mu.Lock()
	if sess.upstreamConn != nil {
		sess.mu.Unlock()
		_ = conn.Close()
		return nil
	}
	sess.upstreamConn = conn
	sess.mu.Unlock()

	go func() {
		if err := sess.upstreamLoop(ctx, conn); err != nil && ctx.Err() == nil {
			log.Printf("upstream loop for session %d: %v", sess.id, err)
		}
	}()
	return nil
}

func (sess *session) forwardUpstream(payload []byte) error {
	sess.mu.Lock()
	conn := sess.upstreamConn
	sess.lastSeen = time.Now()
	sess.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("session %d has no upstream socket yet", sess.id)
	}
	_, err := conn.Write(payload)
	return err
}

func (sess *session) upstreamLoop(ctx context.Context, conn *net.UDPConn) error {
	buf := make([]byte, sess.server.cfg.UpstreamReadBufferSize)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		ack := sess.uplinkRecv.Snapshot()
		sess.mu.Lock()
		sess.nextDownSeq++
		seq := sess.nextDownSeq
		packet := protocol.Packet{
			Type:      protocol.TypeData,
			SessionID: sess.id,
			Seq:       seq,
			Ack:       ack.Ack,
			AckBits:   ack.Bits,
			Payload:   payload,
		}
		down := &downPacket{packet: packet}
		sess.downSent[seq] = down
		sess.lastSeen = time.Now()
		sess.mu.Unlock()
		if err := sess.sendDownPacket(down); err != nil {
			log.Printf("send downlink session %d seq %d: %v", sess.id, seq, err)
		}
	}
}

func (sess *session) handlePeerAck(ack protocol.AckState) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	for seq := range sess.downSent {
		if ack.Acks(seq) {
			delete(sess.downSent, seq)
		}
	}
}

func (sess *session) sendDownPacket(packet *downPacket) error {
	sess.mu.Lock()
	if !sess.hasInfo {
		sess.mu.Unlock()
		return fmt.Errorf("session %d has no client info", sess.id)
	}
	info := sess.info
	sess.lastSeen = time.Now()
	sess.mu.Unlock()

	rawPacket, err := packet.packet.Marshal(sess.server.secret)
	if err != nil {
		return err
	}
	fragments, err := protocol.FragmentPacket(rawPacket, sess.id, packet.packet.Seq, sess.server.cfg.DownlinkPayloadBytes, sess.server.cfg.DownlinkParityShards, 0)
	if err != nil {
		return err
	}
	srcIP := net.IP(info.SpoofIP[:])
	dstIP := net.IP(info.ClientIP[:])
	for _, fragment := range fragments {
		rawFragment, err := fragment.MarshalBinary()
		if err != nil {
			return err
		}
		if err := sess.server.rawSender.SendIPv4UDP(srcIP, dstIP, int(info.SpoofPort), int(info.ClientPort), sess.server.cfg.SpoofTTL, rawFragment); err != nil {
			return err
		}
	}
	sess.mu.Lock()
	packet.lastSent = time.Now()
	packet.attempts++
	sess.mu.Unlock()
	return nil
}
