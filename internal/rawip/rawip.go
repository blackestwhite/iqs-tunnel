package rawip

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

type Sender struct {
	fd int
}

func NewSender() (*Sender, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return &Sender{fd: fd}, nil
}

func (s *Sender) Close() error {
	if s == nil || s.fd == 0 {
		return nil
	}
	err := syscall.Close(s.fd)
	s.fd = 0
	return err
}

func (s *Sender) SendIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort int, ttl int, payload []byte) error {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return fmt.Errorf("spoof sender supports IPv4 only")
	}
	udp := buildUDPPacket(src4, dst4, srcPort, dstPort, payload)
	ip := buildIPv4Header(len(udp), src4, dst4, ttl)
	packet := append(ip, udp...)
	var addr [4]byte
	copy(addr[:], dst4)
	return syscall.Sendto(s.fd, packet, 0, &syscall.SockaddrInet4{Addr: addr})
}

func buildUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte) []byte {
	udpLen := 8 + len(payload)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	pseudo := make([]byte, 12+udpLen)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpLen))
	copy(pseudo[12:], udp)
	checksum := checksum(pseudo)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return udp
}

func buildIPv4Header(payloadLen int, srcIP, dstIP net.IP, ttl int) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], uint16(20+payloadLen))
	binary.BigEndian.PutUint16(header[4:6], 0)
	binary.BigEndian.PutUint16(header[6:8], 0x4000)
	if ttl <= 0 {
		ttl = 64
	}
	header[8] = byte(ttl)
	header[9] = 17
	copy(header[12:16], srcIP.To4())
	copy(header[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(header[10:12], checksum(header))
	return header
}

func checksum(raw []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(raw); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(raw[i : i+2]))
	}
	if len(raw)%2 == 1 {
		sum += uint32(raw[len(raw)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
