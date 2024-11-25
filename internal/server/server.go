package server

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/neokofg/go-pet-vpn-server/internal/server/config"
	"github.com/neokofg/go-pet-vpn-server/internal/server/models"
	"github.com/neokofg/go-pet-vpn-server/internal/server/protocol"
	"github.com/songgao/water"
	"golang.org/x/crypto/chacha20poly1305"
	"gorm.io/gorm"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	MaxConcurrentClients = 100
	ReadTimeout          = 30 * time.Second
	WriteTimeout         = 10 * time.Second
	MaxPacketSize        = 1500
)

type ServerStats struct {
	ActiveClients   int64
	PacketsReceived int64
	PacketsSent     int64
	BytesReceived   int64
	BytesSent       int64
	sync.RWMutex
}

func CheckRootPrivileges() error {
	if runtime.GOOS != "windows" {
		if os.Geteuid() != 0 {
			return fmt.Errorf("this program must be run as root (sudo)")
		}
	}
	return nil
}

type Client struct {
	ID          uint
	Token       string
	TCPConn     net.Conn
	UDPAddr     *net.UDPAddr
	CipherKey   []byte
	ClientNonce [24]byte
	ServerNonce [24]byte
	SequenceNum uint64
	LastSeen    time.Time
	AEAD        cipher.AEAD
	Ctx         context.Context
	Cancel      context.CancelFunc
	sync.RWMutex
	AssignedIP net.IP
}

func (c *Client) WriteTUN(tun *TUNDevice, packet []byte) error {
	// Проверяем, что это IPv4 пакет и он достаточного размера
	if len(packet) < 20 {
		return fmt.Errorf("packet too small: %d bytes", len(packet))
	}

	version := packet[0] >> 4
	if version != 4 {
		return fmt.Errorf("invalid IP version: %d", version)
	}

	// Проверяем длину пакета
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength > len(packet) {
		return fmt.Errorf("declared length %d greater than packet size %d", totalLength, len(packet))
	}

	// Проверяем, что IP назначения соответствует нашей VPN сети
	dstIP := net.IP(packet[16:20])
	if !tun.config.Network.Contains(dstIP) && !isBroadcast(dstIP, tun.config.Network) {
		return fmt.Errorf("destination IP %s not in VPN network %s", dstIP, tun.config.Network)
	}

	// Записываем пакет в TUN интерфейс
	n, err := tun.Write(packet)
	if err != nil {
		return fmt.Errorf("error writing to TUN: %v", err)
	}

	if n != len(packet) {
		return fmt.Errorf("short write to TUN: wrote %d bytes, expected %d", n, len(packet))
	}

	log.Printf("Successfully wrote packet to TUN: dst=%s, size=%d", dstIP, n)
	return nil
}

// isBroadcast checks if the IP is a broadcast address for the given network
func isBroadcast(ip net.IP, network *net.IPNet) bool {
	if ip == nil || network == nil {
		return false
	}
	
	// Get the IP in 4-byte format
	ip = ip.To4()
	if ip == nil {
		return false
	}
	
	// Calculate broadcast address for the network
	broadcast := make(net.IP, 4)
	for i := range broadcast {
		broadcast[i] = network.IP[i] | ^network.Mask[i]
	}
	
	return ip.Equal(broadcast)
}

func dumpPacket(data []byte) {
	if len(data) < 20 {
		log.Printf("Packet too small to dump: %d bytes", len(data))
		return
	}

	version := data[0] >> 4
	ihl := data[0] & 0x0F
	tos := data[1]
	totalLength := binary.BigEndian.Uint16(data[2:4])
	id := binary.BigEndian.Uint16(data[4:6])
	flags := data[6] >> 5
	fragOffset := binary.BigEndian.Uint16(data[6:8]) & 0x1FFF
	ttl := data[8]
	protocol := data[9]
	checksum := binary.BigEndian.Uint16(data[10:12])
	srcIP := net.IP(data[12:16])
	dstIP := net.IP(data[16:20])

	log.Printf("IP Packet Dump:")
	log.Printf("  Version: %d", version)
	log.Printf("  IHL: %d", ihl)
	log.Printf("  ToS: %d", tos)
	log.Printf("  Total Length: %d", totalLength)
	log.Printf("  ID: %d", id)
	log.Printf("  Flags: %d", flags)
	log.Printf("  Fragment Offset: %d", fragOffset)
	log.Printf("  TTL: %d", ttl)
	log.Printf("  Protocol: %d", protocol)
	log.Printf("  Checksum: 0x%04x", checksum)
	log.Printf("  Source IP: %s", srcIP)
	log.Printf("  Destination IP: %s", dstIP)
}

type Server struct {
	cfg          *config.Config
	db           *gorm.DB
	tcpListener  net.Listener
	udpConn      *net.UDPConn
	clients      map[string]*Client
	clientsMutex sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	tunInterface *TUNDevice
	ipPool       *IPPool
	stats        *ServerStats
}

func (s *Server) GracefulShutdown(timeout time.Duration) error {
	// Создаем контекст с таймаутом для shutdown
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Отправляем всем клиентам сигнал отключения
	s.clientsMutex.Lock()
	for _, client := range s.clients {
		if client.UDPAddr != nil {
			header := &protocol.PacketHeader{
				Version: protocol.ProtocolVersion,
				Type:    protocol.PacketTypeDisconnect,
			}
			packet := header.Marshal()
			s.udpConn.WriteToUDP(packet, client.UDPAddr)
		}
	}
	s.clientsMutex.Unlock()

	// Ждем завершения всех горутин или таймаута
	done := make(chan struct{})
	go func() {
		s.clientsMutex.Lock()
		for len(s.clients) > 0 {
			s.clientsMutex.Unlock()
			time.Sleep(100 * time.Millisecond)
			s.clientsMutex.Lock()
		}
		s.clientsMutex.Unlock()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func NewServer(cfg *config.Config, db *gorm.DB) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Создаем TCP listener
	tcpListener, err := net.Listen("tcp", cfg.TCPAddr)
	if err != nil {
		cancel()
		return nil, err
	}

	// Создаем UDP connection
	// Явно указываем IPv4
	udpAddr, err := net.ResolveUDPAddr("udp4", cfg.UDPAddr)
	if err != nil {
		tcpListener.Close()
		cancel()
		return nil, err
	}

	log.Printf("Creating UDP listener on address: %v", udpAddr)
	udpConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		tcpListener.Close()
		cancel()
		return nil, err
	}

	s := &Server{
		cfg:         cfg,
		db:          db,
		tcpListener: tcpListener,
		udpConn:     udpConn,
		clients:     make(map[string]*Client),
		ctx:         ctx,
		cancel:      cancel,
		stats:       &ServerStats{},
	}

	return s, nil
}

func (s *Server) Start(tunCfg *TunnelConfig) error {
	// Проверяем root права
	if err := CheckRootPrivileges(); err != nil {
		return fmt.Errorf("insufficient privileges: %v", err)
	}

	log.Printf("Starting VPN server with config: %+v", tunCfg)

	// Парсим CIDR для Network конфигурации
	_, ipNet, err := net.ParseCIDR(tunCfg.CIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}

	// Сохраняем сетевую конфигурацию
	s.cfg.Network = ipNet

	// Очищаем старую конфигурацию
	if err := cleanupOldConfig(tunCfg.Interface, tunCfg.CIDR); err != nil {
		log.Printf("Warning during cleanup: %v", err)
	}

	// Даем системе время на очистку ресурсов
	time.Sleep(time.Second)

	// Инициализируем IP пул
	ipPool, err := NewIPPool(tunCfg.CIDR)
	if err != nil {
		return fmt.Errorf("failed to create IP pool: %v", err)
	}
	s.ipPool = ipPool

	// Создаем и настраиваем TUN интерфейс
	tunDevice, err := s.setupTunnel(tunCfg)
	if err != nil {
		return fmt.Errorf("failed to setup TUN interface: %v", err)
	}
	s.tunInterface = tunDevice

	// Даем системе время на применение настроек
	time.Sleep(time.Second)

	// Настраиваем маршрутизацию
	if err := s.setupRouting(tunCfg); err != nil {
		s.cleanupRouting(tunCfg)
		return fmt.Errorf("failed to setup routing: %v", err)
	}

	// Запускаем все обработчики
	go s.handleTCPConnections()
	go s.handleUDPPackets()
	go s.handleTunToUDP(tunDevice)
	go s.cleanupInactiveClients()

	log.Printf("Server started successfully. TCP: %s, UDP: %s, TUN: %s, Network: %s",
		s.cfg.TCPAddr, s.cfg.UDPAddr, tunCfg.Interface, tunCfg.CIDR)

	// Проверяем состояние системы
	go s.monitorSystemState(tunCfg)

	<-s.ctx.Done()
	return nil
}

func (s *Server) checkNetworkConfig() error {
	// Проверяем наличие необходимых утилит
	requiredCommands := []string{"ip", "iptables", "sysctl"}
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command not found: %s", cmd)
		}
	}

	// Проверяем поддержку TUN
	if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
		return fmt.Errorf("TUN/TAP device not found: /dev/net/tun")
	}

	// Проверяем права на выполнение команд
	cmd := exec.Command("ip", "link", "list")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("insufficient permissions to run ip command: %v", err)
	}

	cmd = exec.Command("iptables", "-L")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("insufficient permissions to run iptables: %v", err)
	}

	// Проверяем статус systemd-networkd
	cmd = exec.Command("systemctl", "status", "systemd-networkd")
	output, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), "Active: active") {
		log.Printf("Warning: systemd-networkd is running and might interfere with VPN")
	}

	return nil
}

func (s *Server) monitorSystemState(cfg *TunnelConfig) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			// Проверяем состояние интерфейса
			if iface, err := net.InterfaceByName(cfg.Interface); err != nil {
				log.Printf("Warning: interface check failed: %v", err)
			} else {
				log.Printf("Interface %s state: %v", cfg.Interface, iface.Flags)
			}

			// Проверяем маршруты
			cmd := exec.Command("ip", "route", "show", "dev", cfg.Interface)
			if output, err := cmd.CombinedOutput(); err != nil {
				log.Printf("Warning: route check failed: %v", err)
			} else {
				log.Printf("Routes for %s:\n%s", cfg.Interface, string(output))
			}

			// Проверяем правила iptables
			cmd = exec.Command("iptables", "-L", "FORWARD", "-v", "-n")
			if output, err := cmd.CombinedOutput(); err != nil {
				log.Printf("Warning: iptables check failed: %v", err)
			} else {
				log.Printf("Forward rules:\n%s", string(output))
			}
		}
	}
}

func (s *Server) Stop() {
	s.cancel()
	s.tcpListener.Close()
	s.udpConn.Close()

	// Отключаем всех клиентов
	s.clientsMutex.Lock()
	for _, client := range s.clients {
		client.Cancel()
	}
	s.clientsMutex.Unlock()
}

func (s *Server) AssignIP(client *Client) error {
	ip, err := s.ipPool.Allocate()
	if err != nil {
		return err
	}

	client.AssignedIP = ip
	return nil
}

func (s *Server) ReleaseIP(client *Client) {
	if client.AssignedIP != nil {
		s.ipPool.Release(client.AssignedIP)
		client.AssignedIP = nil
	}
}

func (s *Server) handleTCPConnections() error {
	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return err // Сервер остановлен
			}
			log.Printf("Error accepting TCP connection: %v", err)
			continue
		}

		go s.handleTCPClient(conn)
	}
}

func (s *Server) handleTCPClient(conn net.Conn) {
	defer conn.Close()

	// Устанавливаем таймаут для хендшейка
	conn.SetDeadline(time.Now().Add(protocol.HandshakeTimeout * time.Second))

	// Читаем handshake пакет
	buf := make([]byte, protocol.HeaderSize+120) // Размер заголовка + размер handshake пакета
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Error reading handshake: %v", err)
		return
	}

	header, err := protocol.UnmarshalHeader(buf[:protocol.HeaderSize])
	if err != nil {
		log.Printf("Error parsing header: %v", err)
		return
	}

	if header.Type != protocol.PacketTypeHandshake {
		log.Printf("Expected handshake packet, got: %d", header.Type)
		return
	}

	handshake, err := protocol.UnmarshalHandshake(buf[protocol.HeaderSize:n])
	if err != nil {
		log.Printf("Error parsing handshake: %v", err)
		return
	}

	// Проверяем токен
	token, err := models.ValidateToken(s.db, string(handshake.Token[:]))
	if err != nil {
		log.Printf("Invalid token: %v", err)
		return
	}

	// Генерируем ключ шифрования и nonce сервера
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		log.Printf("Error generating key: %v", err)
		return
	}

	var serverNonce [24]byte
	if _, err := rand.Read(serverNonce[:]); err != nil {
		log.Printf("Error generating nonce: %v", err)
		return
	}

	// Создаем AEAD cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Printf("Error creating AEAD: %v", err)
		return
	}

	// Создаем контекст для клиента
	ctx, cancel := context.WithCancel(s.ctx)

	// Назначаем IP адрес клиенту
	assignedIP, err := s.ipPool.Allocate()
	if err != nil {
		log.Printf("Failed to allocate IP: %v", err)
		cancel()
		return
	}

	if assignedIP[len(assignedIP)-1] == 0 {
		assignedIP[len(assignedIP)-1] = 2 // Используем .2 как первый клиентский адрес
	}

	log.Printf("Allocating IP %s to client %s", assignedIP.String(), token.Token)

	// Создаем клиента
	client := &Client{
		ID:          token.UserID,
		Token:       token.Token,
		TCPConn:     conn,
		CipherKey:   key,
		ClientNonce: handshake.ClientNonce,
		ServerNonce: serverNonce,
		AEAD:        aead,
		LastSeen:    time.Now(),
		Ctx:         ctx,
		Cancel:      cancel,
		AssignedIP:  assignedIP,
	}

	// Добавляем клиента в map
	s.clientsMutex.Lock()
	s.clients[token.Token] = client
	s.clientsMutex.Unlock()

	// Отправляем ответ на handshake
	response := &protocol.HandshakeResponse{
		ServerNonce: serverNonce,
		Key:         [32]byte(key),
	}

	// Копируем IP адрес в ответ
	copy(response.AssignedIP[:], assignedIP.To4())

	// Устанавливаем маску подсети
	if s.cfg.Network != nil {
		copy(response.SubnetMask[:], s.cfg.Network.Mask)
	} else {
		// Используем маску по умолчанию /24 если сеть не настроена
		mask := net.CIDRMask(24, 32)
		copy(response.SubnetMask[:], mask)
	}

	responseData := response.Marshal()
	responseHeader := &protocol.PacketHeader{
		Version:     protocol.ProtocolVersion,
		Type:        protocol.PacketTypeHandshake,
		SequenceNum: 0,
		PayloadSize: uint32(len(responseData)),
	}

	// Отправляем ответ
	headerData := responseHeader.Marshal()
	if _, err := conn.Write(append(headerData, responseData...)); err != nil {
		log.Printf("Error sending handshake response: %v", err)
		cancel()
		s.clientsMutex.Lock()
		delete(s.clients, token.Token)
		s.clientsMutex.Unlock()
		s.ipPool.Release(assignedIP)
		return
	}

	// Снимаем таймаут после успешного хендшейка
	conn.SetDeadline(time.Time{})

	log.Printf("Client connected: %s with IP: %s", token.Token, assignedIP)
}

func (s *Server) handleUDPPackets() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in handleUDPPackets: %v", r)
		}
	}()

	log.Printf("Starting UDP packet handler on %v", s.udpConn.LocalAddr())
	buf := make([]byte, protocol.MaxPacketSize)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			n, addr, err := s.udpConn.ReadFromUDP(buf)
			if err != nil {
				if s.ctx.Err() != nil {
					return
				}
				log.Printf("Error reading UDP packet: %v", err)
				continue
			}

			log.Printf("Received UDP packet: from=%v size=%d", addr, n)
			go s.handleUDPPacket(buf[:n], addr) // Убрали проверку ошибки, так как обработка идет в горутине
		}
	}
}

func (s *Server) handleUDPPacket(packet []byte, addr *net.UDPAddr) error {
	if len(packet) < protocol.HeaderSize {
		return fmt.Errorf("received packet too small: %d bytes", len(packet))
	}

	log.Printf("Received UDP packet from %v, size: %d bytes", addr, len(packet))

	// Parse packet header
	header, err := protocol.UnmarshalHeader(packet[:protocol.HeaderSize])
	if err != nil {
		return fmt.Errorf("failed to unmarshal packet header: %v", err)
	}

	log.Printf("Packet header: version=%d, type=%d, sequence=%d, payload_size=%d",
		header.Version, header.Type, header.SequenceNum, header.PayloadSize)

	// Check protocol version
	if header.Version != protocol.ProtocolVersion {
		return fmt.Errorf("unsupported protocol version: %d", header.Version)
	}

	// Find the client by UDP address
	s.clientsMutex.RLock()
	var client *Client
	for _, c := range s.clients {
		if c.UDPAddr != nil && c.UDPAddr.String() == addr.String() {
			client = c
			break
		}
	}
	s.clientsMutex.RUnlock()

	// If client not found by UDP address, try to find by decrypting the packet
	if client == nil && header.Type == protocol.PacketTypeData {
		s.clientsMutex.RLock()
		for _, c := range s.clients {
			log.Printf("Trying to decrypt with client %s", c.Token)
			nonce := make([]byte, chacha20poly1305.NonceSize)
			copy(nonce, c.ClientNonce[:])
			binary.BigEndian.PutUint64(nonce[len(nonce)-8:], header.SequenceNum)

			decrypted, decryptErr := c.AEAD.Open(nil, nonce, packet[protocol.HeaderSize:], nil)
			if decryptErr == nil && len(decrypted) >= 20 {
				client = c
				c.UDPAddr = addr
				log.Printf("Associated UDP address %s with client %s", addr.String(), c.Token)
				break
			}
			log.Printf("Failed to decrypt with client %s: %v", c.Token, decryptErr)
		}
		s.clientsMutex.RUnlock()
	}

	if client == nil {
		return fmt.Errorf("no client found for address: %v", addr)
	}

	switch header.Type {
	case protocol.PacketTypeData:
		encryptedData := packet[protocol.HeaderSize:]
		log.Printf("Attempting to decrypt data packet: encrypted_size=%d, from_client=%v", 
			len(encryptedData), addr)

		// Create nonce for decryption
		nonce := make([]byte, chacha20poly1305.NonceSize)
		copy(nonce, client.ClientNonce[:])
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], header.SequenceNum)

		// Decrypt the data
		decrypted, err := client.AEAD.Open(nil, nonce, encryptedData, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt packet from %v: %v", addr, err)
		}

		log.Printf("Successfully decrypted packet: size=%d bytes, from_client=%v", 
			len(decrypted), addr)

		// Write decrypted data to TUN
		if _, err := s.tunInterface.Write(decrypted); err != nil {
			return fmt.Errorf("failed to write to TUN: %v", err)
		}

		log.Printf("Successfully wrote decrypted packet to TUN interface")
		return nil

	case protocol.PacketTypeKeepalive:
		log.Printf("Received keepalive from %s", addr.String())
		return nil

	case protocol.PacketTypeDisconnect:
		log.Printf("Received disconnect from %s", addr.String())
		s.clientsMutex.Lock()
		delete(s.clients, client.Token)
		s.clientsMutex.Unlock()
		s.ReleaseIP(client)
		client.Cancel()
		return nil

	default:
		return fmt.Errorf("unknown packet type: %d", header.Type)
	}
}

func (s *Server) cleanupInactiveClients() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.clientsMutex.Lock()
			for token, client := range s.clients {
				client.RLock()
				if now.Sub(client.LastSeen) > 2*time.Minute {
					client.RUnlock()
					client.Cancel()
					delete(s.clients, token)
					log.Printf("Cleaned up inactive client: %s", token)
				} else {
					client.RUnlock()
				}
			}
			s.clientsMutex.Unlock()
		}
	}
}

type TUNDevice struct {
	*water.Interface
	name   string
	config *TUNConfig
}

type TUNConfig struct {
	Name    string
	MTU     int
	Address net.IP
	Network *net.IPNet
	Routes  []Route
}

type Route struct {
	Network *net.IPNet
	Gateway net.IP
}

func NewTUN(config *TUNConfig) (*TUNDevice, error) {
	log.Printf("Creating TUN interface %s...", config.Name)

	// Create water config
	cfg := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name:       config.Name,
			Persist:    true, // Make the interface persistent
			MultiQueue: true, // Bring up the interface immediately
		},
	}

	ifce, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %v", err)
	}

	tun := &TUNDevice{
		Interface: ifce,
		name:      ifce.Name(),
		config:    config,
	}

	// Wait a bit before configuring
	time.Sleep(time.Second)

	log.Printf("Configuring TUN interface %s...", tun.name)
	if err := tun.configure(); err != nil {
		tun.Close()
		return nil, err
	}

	// Check the interface state after configuration
	iface, err := net.InterfaceByName(tun.name)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("failed to get interface state: %v", err)
	}

	log.Printf("Interface %s flags: %v", tun.name, iface.Flags)
	return tun, nil
}

func (t *TUNDevice) configure() error {
	switch runtime.GOOS {
	case "linux":
		return t.configureLinux()
	case "darwin":
		return t.configureDarwin()
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func (t *TUNDevice) configureLinux() error {
	// Wait a bit before configuring
	time.Sleep(time.Second)

	// Disable IPv6
	if err := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=1", t.name)).Run(); err != nil {
		log.Printf("Warning: failed to disable IPv6: %v", err)
	}

	// Bring up the interface and set MTU
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "up", "mtu", fmt.Sprintf("%d", t.config.MTU))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set interface up: %v, output: %s", err, output)
	}

	// Wait and check the interface state
	maxAttempts := 5
	for i := 0; i < maxAttempts; i++ {
		time.Sleep(time.Second)
		
		iface, err := net.InterfaceByName(t.name)
		if err != nil {
			log.Printf("Warning: attempt %d/%d - failed to get interface: %v", i+1, maxAttempts, err)
			continue
		}
		
		if iface.Flags&net.FlagUp != 0 {
			log.Printf("Interface %s is up after %d seconds", t.name, i+1)
			break
		}
		
		if i == maxAttempts-1 {
			return fmt.Errorf("interface failed to come up after %d attempts", maxAttempts)
		}
	}

	// Set IP address
	addr := fmt.Sprintf("%s/%d", t.config.Address.String(), maskBits(t.config.Network.Mask))
	cmd = exec.Command("ip", "addr", "add", addr, "dev", t.name)
	if output, err := cmd.CombinedOutput(); err != nil {
		// If the address already exists, try to replace it
		cmd = exec.Command("ip", "addr", "replace", addr, "dev", t.name)
		if output, err = cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set address: %v, output: %s", err, output)
		}
	}

	// Check IP address assignment
	maxAttempts = 5
	for i := 0; i < maxAttempts; i++ {
		time.Sleep(time.Second)
		
		iface, err := net.InterfaceByName(t.name)
		if err != nil {
			log.Printf("Warning: attempt %d/%d - failed to get interface: %v", i+1, maxAttempts, err)
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("Warning: attempt %d/%d - failed to get addresses: %v", i+1, maxAttempts, err)
			continue
		}
		
		for _, a := range addrs {
			if strings.Contains(a.String(), t.config.Address.String()) {
				log.Printf("Address %s configured successfully on %s", addr, t.name)
				return nil
			}
		}
		
		if i == maxAttempts-1 {
			return fmt.Errorf("failed to verify IP address configuration after %d attempts", maxAttempts)
		}
	}

	return nil
}

func (t *TUNDevice) configureDarwin() error {
	// Bring up the interface and set IP
	addr := fmt.Sprintf("%s/%d", t.config.Address.String(), maskBits(t.config.Network.Mask))
	if err := exec.Command("ifconfig", t.name, addr, "up").Run(); err != nil {
		return fmt.Errorf("failed to configure interface: %v", err)
	}

	// Set MTU
	if err := exec.Command("ifconfig", t.name, "mtu", fmt.Sprintf("%d", t.config.MTU)).Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	// Add routes
	for _, route := range t.config.Routes {
		args := []string{"-n", "add", "-net", route.Network.String()}
		if route.Gateway != nil {
			args = append(args, route.Gateway.String())
		} else {
			args = append(args, "-interface", t.name)
		}

		if err := exec.Command("route", args...).Run(); err != nil {
			return fmt.Errorf("failed to add route: %v", err)
		}
	}

	return nil
}

func maskBits(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

func (t *TUNDevice) ReadPacket() ([]byte, error) {
	buffer := make([]byte, t.config.MTU)
	n, err := t.Read(buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:n], nil
}

func (t *TUNDevice) WritePacket(packet []byte) error {
	_, err := t.Write(packet)
	return err
}

func (t *TUNDevice) Close() error {
	// Remove routes
	if runtime.GOOS == "linux" {
		for _, route := range t.config.Routes {
			exec.Command("ip", "route", "del", route.Network.String(), "dev", t.name).Run()
		}
	} else if runtime.GOOS == "darwin" {
		for _, route := range t.config.Routes {
			exec.Command("route", "-n", "delete", "-net", route.Network.String()).Run()
		}
	}

	return t.Interface.Close()
}

type TunnelConfig struct {
	Interface string // Имя TUN интерфейса
	CIDR      string // CIDR для туннеля (например, "10.0.0.0/24")
	MTU       int    // MTU для интерфейса
}

func (s *Server) setupTunnel(cfg *TunnelConfig) (*TUNDevice, error) {
	// Parse CIDR
	_, network, err := net.ParseCIDR(cfg.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %v", err)
	}

	// Generate server IP address (first address in the network)
	serverIP := make(net.IP, len(network.IP))
	copy(serverIP, network.IP)
	serverIP[len(serverIP)-1] |= 1

	// TUN interface configuration
	tunConfig := &TUNConfig{
		Name:    cfg.Interface,
		MTU:     cfg.MTU,
		Address: serverIP,
		Network: network,
		Routes: []Route{
			{
				Network: network,
				Gateway: nil, // Route through the interface
			},
		},
	}

	// Create TUN interface
	tun, err := NewTUN(tunConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %v", err)
	}

	// Reserve the first address for the server
	s.ipPool.Reserve(serverIP)

	return tun, nil
}

func (s *Server) handleTunToUDP(tun *TUNDevice) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in handleTunToUDP: %v", r)
		}
	}()

	buffer := make([]byte, MaxPacketSize)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			n, err := tun.Read(buffer)
			if err != nil {
				if s.ctx.Err() != nil {
					return
				}
				log.Printf("Error reading from TUN: %v", err)
				continue
			}

			packet := buffer[:n]
			
			// Check if it's an Ethernet frame
			var ipPacket []byte
			if len(packet) >= 14 {
				etherType := binary.BigEndian.Uint16(packet[12:14])
				if etherType == 0x0800 { // IPv4
					ipPacket = packet[14:]
				} else if etherType == 0x0806 { // ARP
					log.Printf("Received ARP packet, handling...")
					if err := s.handleARPPacket(packet[14:]); err != nil {
						log.Printf("Error handling ARP packet: %v", err)
					}
					continue
				} else {
					log.Printf("Unknown EtherType: 0x%04x", etherType)
					continue
				}
			} else {
				ipPacket = packet
			}

			// Check if it's an IPv4 packet
			if len(ipPacket) < 20 {
				log.Printf("Packet too short for IPv4: %d bytes", len(ipPacket))
				continue
			}

			version := ipPacket[0] >> 4
			if version != 4 {
				log.Printf("Not an IPv4 packet: version=%d", version)
				continue
			}

			// Get destination IP address
			dstIP := net.IP(ipPacket[16:20])
			srcIP := net.IP(ipPacket[12:16])
			protocol := ipPacket[9]
			length := binary.BigEndian.Uint16(ipPacket[2:4])
			
			log.Printf("Processing packet: Protocol=%d, Src=%s, Dst=%s, Length=%d",
				protocol, srcIP, dstIP, length)

			// Find the client by IP
			s.clientsMutex.RLock()
			var targetClient *Client
			for _, client := range s.clients {
				if client.AssignedIP != nil && client.AssignedIP.Equal(dstIP) {
					targetClient = client
					break
				}
			}
			s.clientsMutex.RUnlock()

			if targetClient == nil {
				log.Printf("No client found for IP %s", dstIP)
				continue
			}

			// Send only the IP packet to the client
			if err := s.sendPacketToClient(targetClient, ipPacket); err != nil {
				log.Printf("Error sending packet to client %s: %v", targetClient.AssignedIP, err)
			} else {
				log.Printf("Successfully sent packet to client %s", targetClient.AssignedIP)
			}
		}
	}
}

func (s *Server) handleARPPacket(packet []byte) error {
	if len(packet) < 28 {
		return fmt.Errorf("ARP packet too short: %d bytes", len(packet))
	}

	// Analyze ARP packet
	protocolType := binary.BigEndian.Uint16(packet[2:4])
	operation := binary.BigEndian.Uint16(packet[6:8])

	// Get IP addresses
	senderIP := net.IP(packet[14:18])
	targetIP := net.IP(packet[24:28])

	log.Printf("ARP: op=%d, sender=%s, target=%s", operation, senderIP, targetIP)

	// Check if it's an IPv4 ARP
	if protocolType != 0x0800 {
		return fmt.Errorf("unsupported protocol type in ARP: 0x%04x", protocolType)
	}

	// If it's an ARP request to the server or another client in the VPN network
	if operation == 1 { // ARP Request
		// Create an ARP response
		reply := make([]byte, 28)
		copy(reply, packet) // Copy the header

		// Change the operation type to response
		binary.BigEndian.PutUint16(reply[6:8], 2) // ARP Reply

		// Swap the MAC and IP addresses
		copy(reply[8:14], packet[18:24])  // Target MAC -> Sender MAC
		copy(reply[14:18], targetIP)      // Target IP -> Sender IP
		copy(reply[18:24], packet[8:14])  // Sender MAC -> Target MAC
		copy(reply[24:28], senderIP)      // Sender IP -> Target IP

		// Send the response through TUN
		if _, err := s.tunInterface.Write(reply); err != nil {
			return fmt.Errorf("failed to send ARP reply: %v", err)
		}
	}

	return nil
}

func (s *Server) sendPacketToClient(client *Client, packet []byte) error {
	client.Lock()
	defer client.Unlock()

	if client.UDPAddr == nil {
		return fmt.Errorf("client UDP address not set")
	}

	// Create nonce for encryption
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, client.ServerNonce[:])
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], client.SequenceNum)

	// Encrypt the packet
	encrypted := client.AEAD.Seal(nil, nonce, packet, nil)

	// Create header
	header := &protocol.PacketHeader{
		Version:     protocol.ProtocolVersion,
		Type:        protocol.PacketTypeData,
		SequenceNum: client.SequenceNum,
		PayloadSize: uint32(len(encrypted)),
	}

	// Increment sequence number
	client.SequenceNum++

	// Form the full packet
	fullPacket := append(header.Marshal(), encrypted...)

	// Send the packet
	_, err := s.udpConn.WriteToUDP(fullPacket, client.UDPAddr)
	return err
}

func (s *Server) handleEncryptedPacket(client *Client, header *protocol.PacketHeader, encryptedData []byte) error {
	// Create nonce from ClientNonce and SequenceNum
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, client.ClientNonce[:])
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], header.SequenceNum)

	// Decrypt the data
	decrypted, err := client.AEAD.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return err
	}

	// Write decrypted packet to TUN interface
	_, err = s.tunInterface.Write(decrypted)
	return err
}

type IPPool struct {
	network *net.IPNet
	used    map[string]bool
	mu      sync.Mutex
}

func NewIPPool(cidr string) (*IPPool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	return &IPPool{
		network: network,
		used:    make(map[string]bool),
	}, nil
}

func (p *IPPool) Reserve(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.used[ip.String()] = true
}

func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Start with the first available address in the network
	ip := make(net.IP, len(p.network.IP))
	copy(ip, p.network.IP)

	// Iterate through addresses until we find a free one
	for {
		if !p.used[ip.String()] {
			p.used[ip.String()] = true
			return ip, nil
		}

		// Increment IP by 1
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] != 0 {
				break
			}
		}

		// Check if the address is still in our network
		if !p.network.Contains(ip) {
			return nil, errors.New("ip pool exhausted")
		}
	}
}

func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, ip.String())
}

func (s *Server) setupRouting(cfg *TunnelConfig) error {
	if runtime.GOOS == "linux" {
		return s.setupLinuxRouting(cfg)
	} else if runtime.GOOS == "darwin" {
		return s.setupDarwinRouting(cfg)
	}
	return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
}

func (s *Server) setupLinuxRouting(cfg *TunnelConfig) error {
	// Enable IP forwarding
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	// Get the default interface
	defaultIface, err := getDefaultInterface()
	if err != nil {
		return fmt.Errorf("failed to get default interface: %v", err)
	}

	log.Printf("Using default interface: %s", defaultIface)

	// First, try to remove old rules (ignore errors)
	cleanupCommands := [][]string{
		{"iptables", "-t", "nat", "-D", "POSTROUTING", "-s", cfg.CIDR, "-j", "MASQUERADE"},
		{"iptables", "-D", "FORWARD", "-i", cfg.Interface, "-j", "ACCEPT"},
		{"iptables", "-D", "FORWARD", "-o", cfg.Interface, "-j", "ACCEPT"},
		{"iptables", "-D", "INPUT", "-i", cfg.Interface, "-j", "ACCEPT"},
		{"iptables", "-D", "OUTPUT", "-o", cfg.Interface, "-j", "ACCEPT"},
	}

	for _, cmd := range cleanupCommands {
		_ = exec.Command(cmd[0], cmd[1:]...).Run()
	}

	// Add new rules
	setupCommands := [][]string{
		// Allow NAT for the VPN network
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", cfg.CIDR, "-o", defaultIface, "-j", "MASQUERADE"},
		// Allow forwarding
		{"iptables", "-A", "FORWARD", "-i", cfg.Interface, "-j", "ACCEPT"},
		{"iptables", "-A", "FORWARD", "-o", cfg.Interface, "-j", "ACCEPT"},
		// Allow incoming and outgoing traffic for the VPN
		{"iptables", "-A", "INPUT", "-i", cfg.Interface, "-j", "ACCEPT"},
		{"iptables", "-A", "OUTPUT", "-o", cfg.Interface, "-j", "ACCEPT"},
	}

	// Apply new rules
	for _, cmd := range setupCommands {
		if output, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("failed to setup iptables rule '%v': %v (output: %s)", cmd, err, string(output))
		}
	}

	// Configure routing for the VPN network
	log.Printf("Adding route for VPN network %s via interface %s", cfg.CIDR, cfg.Interface)
	
	// Check if the interface exists and is up
	maxAttempts := 5
	for i := 0; i < maxAttempts; i++ {
		ifaceCmd := exec.Command("ip", "link", "show", cfg.Interface)
		if output, err := ifaceCmd.CombinedOutput(); err != nil {
			if i == maxAttempts-1 {
				return fmt.Errorf("interface %s is not ready after %d attempts: %v (output: %s)", 
					cfg.Interface, maxAttempts, err, string(output))
			}
			log.Printf("Warning: attempt %d/%d - interface not ready: %v", i+1, maxAttempts, err)
			time.Sleep(time.Second)
			continue
		}
		break
	}
	
	// First, try to delete the existing route
	delRouteCmd := exec.Command("ip", "route", "del", cfg.CIDR)
	_ = delRouteCmd.Run() // Ignore errors when deleting

	// Now add the new route
	for i := 0; i < maxAttempts; i++ {
		addRouteCmd := exec.Command("ip", "route", "add", cfg.CIDR, "dev", cfg.Interface)
		if output, err := addRouteCmd.CombinedOutput(); err != nil {
			if i == maxAttempts-1 {
				return fmt.Errorf("failed to add route after %d attempts: %v (output: %s)", 
					maxAttempts, err, string(output))
			}
			log.Printf("Warning: attempt %d/%d - failed to add route: %v", i+1, maxAttempts, err)
			time.Sleep(time.Second)
			continue
		}
		log.Printf("Route added successfully for %s via %s", cfg.CIDR, cfg.Interface)
		break
	}

	log.Printf("Routing and NAT configured successfully")
	return nil
}

func (s *Server) setupDarwinRouting(cfg *TunnelConfig) error {
	// Enable IP forwarding
	if err := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	// Configure NAT using pfctl
	pf := fmt.Sprintf(`
nat on en0 from %s to any -> (en0)
pass in on %s all
pass out on %s all
    `, cfg.CIDR, cfg.Interface, cfg.Interface)

	// Write rules to a temporary file
	tmpfile, err := os.CreateTemp("", "pf.conf")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(pf); err != nil {
		return fmt.Errorf("failed to write pf rules: %v", err)
	}

	// Load rules
	if err := exec.Command("pfctl", "-f", tmpfile.Name()).Run(); err != nil {
		return fmt.Errorf("failed to load pf rules: %v", err)
	}

	// Enable PF
	if err := exec.Command("pfctl", "-e").Run(); err != nil {
		return fmt.Errorf("failed to enable pf: %v", err)
	}

	return nil
}

func (s *Server) cleanupRouting(cfg *TunnelConfig) error {
	if runtime.GOOS == "linux" {
		return s.cleanupLinuxRouting(cfg)
	} else if runtime.GOOS == "darwin" {
		return s.cleanupDarwinRouting(cfg)
	}
	return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
}

func (s *Server) cleanupLinuxRouting(cfg *TunnelConfig) error {
	// Remove NAT rules
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", cfg.CIDR, "-j", "MASQUERADE").Run()

	// Remove forwarding rules
	exec.Command("iptables", "-D", "FORWARD", "-i", cfg.Interface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-o", cfg.Interface, "-j", "ACCEPT").Run()

	return nil
}

func (s *Server) cleanupDarwinRouting(cfg *TunnelConfig) error {
	// Disable PF
	exec.Command("pfctl", "-d").Run()

	return nil
}

// cleanupOldConfig cleans up old VPN configuration
func cleanupOldConfig(interfaceName string, cidr string) error {
	log.Printf("Cleaning up old VPN configuration...")

	// Stop systemd-networkd
	if err := exec.Command("systemctl", "stop", "systemd-networkd").Run(); err != nil {
		log.Printf("Warning: failed to stop systemd-networkd: %v", err)
	}

	// Remove old interface
	cleanupInterface(interfaceName)

	// Wait a bit after removing the interface
	time.Sleep(time.Second * 2)

	// Clean up iptables rules
	cleanupIPTables(interfaceName, cidr)

	// Clean up routes
	cleanupRoutes(interfaceName, cidr)

	return nil
}

// cleanupIPTables cleans up iptables rules
func cleanupIPTables(interfaceName string, cidr string) {
	// Get the default interface
	defaultIface, err := getDefaultInterface()
	if err != nil {
		log.Printf("Warning: couldn't get default interface: %v", err)
		defaultIface = "*" // Use wildcard if we can't get the interface
	}

	rules := [][]string{
		{"iptables", "-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-o", defaultIface, "-j", "MASQUERADE"},
		{"iptables", "-D", "FORWARD", "-i", interfaceName, "-j", "ACCEPT"},
		{"iptables", "-D", "FORWARD", "-o", interfaceName, "-j", "ACCEPT"},
	}

	for _, rule := range rules {
		// Try to remove the rule several times, as there may be multiple
		for i := 0; i < 5; i++ {
			cmd := exec.Command(rule[0], rule[1:]...)
			if _, err := cmd.CombinedOutput(); err != nil {
				break // Rule no longer exists
			}
			log.Printf("Removed iptables rule: %v", rule)
		}
	}
}

// cleanupRoutes cleans up routes
func cleanupRoutes(interfaceName string, cidr string) {
	// Remove all routes for the interface
	cmd := exec.Command("ip", "route", "flush", "dev", interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: couldn't flush routes: %v, output: %s", err, string(output))
	}

	// Additionally, try to remove the specific route
	cmd = exec.Command("ip", "route", "del", cidr, "dev", interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: couldn't delete specific route: %v, output: %s", err, string(output))
	}
}

// cleanupInterface removes the old interface
func cleanupInterface(interfaceName string) {
	cmd := exec.Command("ip", "link", "delete", interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: couldn't delete interface %s: %v, output: %s",
			interfaceName, err, output)
	} else {
		log.Printf("Removed interface: %s", interfaceName)
	}
}

func getDefaultInterface() (string, error) {
	// Try several ways to find the default interface

	// Method 1: through ip route
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err == nil {
		fields := strings.Fields(string(output))
		for i, field := range fields {
			if field == "dev" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
	}

	// Method 2: check popular interfaces
	commonInterfaces := []string{"eth0", "en0", "ens33", "enp0s3", "wlan0", "wlp2s0"}
	for _, ifname := range commonInterfaces {
		iface, err := net.InterfaceByName(ifname)
		if err != nil {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// Check if the interface has an IP address
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				return ifname, nil
			}
		}
	}

	// Method 3: iterate through all interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %v", err)
	}

	for _, iface := range interfaces {
		// Skip loopback and interfaces without the up flag
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				return iface.Name, nil
			}
		}
	}

	return "", errors.New("no suitable network interface found")
}
