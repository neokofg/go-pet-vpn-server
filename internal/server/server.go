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
	if !tun.config.Network.Contains(dstIP) {
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

	return nil
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
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.UDPAddr)
	if err != nil {
		tcpListener.Close()
		cancel()
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
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

			go s.handleUDPPacket(buf[:n], addr) // Убрали проверку ошибки, так как обработка идет в горутине
		}
	}
}

func (s *Server) handleUDPPacket(data []byte, addr *net.UDPAddr) {
	log.Printf("Handling UDP packet from %v, size: %d bytes", addr, len(data))
	
	if len(data) < protocol.HeaderSize {
		log.Printf("Packet too small from %s: %d bytes", addr.String(), len(data))
		return
	}

	header, err := protocol.UnmarshalHeader(data[:protocol.HeaderSize])
	if err != nil {
		log.Printf("Error parsing UDP header from %s: %v", addr.String(), err)
		return
	}

	log.Printf("Received packet type %d from %s, sequence: %d, size: %d",
		header.Type, addr.String(), header.SequenceNum, len(data))

	// Находим клиента
	s.clientsMutex.RLock()
	var targetClient *Client
	for _, client := range s.clients {
		if client.UDPAddr != nil && client.UDPAddr.String() == addr.String() {
			targetClient = client
			break
		}
	}
	s.clientsMutex.RUnlock()

	// Если клиент не найден, проверяем новое подключение
	if targetClient == nil {
		s.clientsMutex.RLock()
		for _, client := range s.clients {
			if client.UDPAddr == nil {
				targetClient = client
				break
			}
		}
		s.clientsMutex.RUnlock()

		if targetClient != nil {
			targetClient.Lock()
			if targetClient.UDPAddr == nil {
				targetClient.UDPAddr = addr
				log.Printf("Associated UDP address %s with client %s", addr.String(), targetClient.Token)
			}
			targetClient.Unlock()
		}
	}

	if targetClient == nil {
		log.Printf("Unknown client from %s", addr.String())
		return
	}

	targetClient.Lock()
	defer targetClient.Unlock()

	targetClient.LastSeen = time.Now()

	switch header.Type {
	case protocol.PacketTypeData:
		if uint32(len(data)) < protocol.HeaderSize+header.PayloadSize {
			log.Printf("Data packet too small from %s: expected %d, got %d",
				addr.String(), protocol.HeaderSize+header.PayloadSize, len(data))
			return
		}

		encryptedData := data[protocol.HeaderSize:]

		// Создаем nonce из ClientNonce и SequenceNum
		nonce := make([]byte, chacha20poly1305.NonceSize)
		copy(nonce, targetClient.ClientNonce[:])
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], header.SequenceNum)

		log.Printf("Decrypting packet: size=%d, nonce=%x", len(encryptedData), nonce)

		// Расшифровываем данные
		decrypted, err := targetClient.AEAD.Open(nil, nonce, encryptedData, nil)
		if err != nil {
			log.Printf("Error decrypting data from %s: %v", addr.String(), err)
			return
		}

		// Проверяем IP пакет
		if len(decrypted) < 20 {
			log.Printf("Decrypted packet too small: %d bytes", len(decrypted))
			return
		}

		version := decrypted[0] >> 4
		if version != 4 {
			log.Printf("Invalid IP version: %d", version)
			return
		}

		// Отладочная информация
		srcIP := net.IP(decrypted[12:16])
		dstIP := net.IP(decrypted[16:20])
		totalLen := binary.BigEndian.Uint16(decrypted[2:4])

		log.Printf("Decrypted packet: version=%d, src=%s, dst=%s, total_len=%d",
			version, srcIP, dstIP, totalLen)

		// Записываем в TUN
		if _, err := s.tunInterface.Write(decrypted); err != nil {
			log.Printf("Error writing to TUN: %v", err)
			return
		}

	case protocol.PacketTypeKeepalive:
		log.Printf("Received keepalive from %s", addr.String())

		// Отправляем keepalive в ответ
		responseHeader := &protocol.PacketHeader{
			Version:     protocol.ProtocolVersion,
			Type:        protocol.PacketTypeKeepalive,
			SequenceNum: targetClient.SequenceNum,
		}
		targetClient.SequenceNum++

		if _, err := s.udpConn.WriteToUDP(responseHeader.Marshal(), addr); err != nil {
			log.Printf("Error sending keepalive response: %v", err)
		}

	case protocol.PacketTypeDisconnect:
		log.Printf("Client disconnected: %s", targetClient.Token)
		targetClient.Cancel()
		s.clientsMutex.Lock()
		delete(s.clients, targetClient.Token)
		s.clientsMutex.Unlock()

	default:
		log.Printf("Unknown packet type %d from %s", header.Type, addr.String())
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

	// Создаем конфигурацию для water
	cfg := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name:       config.Name,
			Persist:    true, // Делаем интерфейс постоянным
			MultiQueue: true, // Поднимаем интерфейс сразу
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

	// Ждем немного перед настройкой
	time.Sleep(time.Second)

	log.Printf("Configuring TUN interface %s...", tun.name)
	if err := tun.configure(); err != nil {
		tun.Close()
		return nil, err
	}

	// Проверяем состояние интерфейса после настройки
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
	// Ждем немного перед настройкой
	time.Sleep(time.Second)

	// Отключаем IPv6
	if err := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=1", t.name)).Run(); err != nil {
		log.Printf("Warning: failed to disable IPv6: %v", err)
	}

	// Поднимаем интерфейс и устанавливаем MTU
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "up", "mtu", fmt.Sprintf("%d", t.config.MTU))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set interface up: %v, output: %s", err, output)
	}

	// Ждем после поднятия интерфейса
	time.Sleep(time.Second)

	// Проверяем состояние
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return fmt.Errorf("failed to get interface after up: %v", err)
	}
	log.Printf("Interface %s state after up: %v", t.name, iface.Flags)

	// Назначаем IP адрес
	addr := fmt.Sprintf("%s/%d", t.config.Address.String(), maskBits(t.config.Network.Mask))
	cmd = exec.Command("ip", "addr", "add", addr, "dev", t.name)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Если адрес уже существует, пробуем его заменить
		cmd = exec.Command("ip", "addr", "replace", addr, "dev", t.name)
		if output, err = cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set address: %v, output: %s", err, output)
		}
	}

	// Ждем после настройки адреса
	time.Sleep(time.Second)

	return nil
}

func (t *TUNDevice) configureDarwin() error {
	// Поднимаем интерфейс и устанавливаем IP
	addr := fmt.Sprintf("%s/%d", t.config.Address.String(), maskBits(t.config.Network.Mask))
	if err := exec.Command("ifconfig", t.name, addr, "up").Run(); err != nil {
		return fmt.Errorf("failed to configure interface: %v", err)
	}

	// Устанавливаем MTU
	if err := exec.Command("ifconfig", t.name, "mtu", fmt.Sprintf("%d", t.config.MTU)).Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	// Добавляем маршруты
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
	// Удаляем маршруты
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
	// Парсим CIDR
	_, network, err := net.ParseCIDR(cfg.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %v", err)
	}

	// Генерируем IP адрес для сервера (первый адрес в сети)
	serverIP := make(net.IP, len(network.IP))
	copy(serverIP, network.IP)
	serverIP[len(serverIP)-1] |= 1

	// Конфигурация TUN интерфейса
	tunConfig := &TUNConfig{
		Name:    cfg.Interface,
		MTU:     cfg.MTU,
		Address: serverIP,
		Network: network,
		Routes: []Route{
			{
				Network: network,
				Gateway: nil, // Маршрутизация через интерфейс
			},
		},
	}

	// Создаем TUN интерфейс
	tun, err := NewTUN(tunConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %v", err)
	}

	// Резервируем первый адрес для сервера
	s.ipPool.Reserve(serverIP)

	return tun, nil
}

func (s *Server) handleTunToUDP(tun *TUNDevice) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in handleTunToUDP: %v", r)
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Читаем пакет из TUN
			packet, err := tun.ReadPacket()
			if err != nil {
				if s.ctx.Err() != nil {
					return
				}
				log.Printf("Error reading from TUN: %v", err)
				continue
			}

			// Проверяем, что это IPv4 пакет
			if len(packet) < 20 || packet[0]>>4 != 4 {
				continue
			}

			// Получаем IP адрес назначения
			dstIP := net.IP(packet[16:20])

			// Находим клиента по IP
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
				continue // Неизвестный получатель
			}

			// Передаем пакет клиенту
			if err := s.sendPacketToClient(targetClient, packet); err != nil {
				log.Printf("Error sending packet to client %s: %v", targetClient.AssignedIP, err)
			}
		}
	}
}

func (s *Server) sendPacketToClient(client *Client, packet []byte) error {
	client.Lock()
	defer client.Unlock()

	if client.UDPAddr == nil {
		return fmt.Errorf("client UDP address not set")
	}

	// Создаем nonce для шифрования
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, client.ServerNonce[:])
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], client.SequenceNum)

	// Шифруем пакет
	encrypted := client.AEAD.Seal(nil, nonce, packet, nil)

	// Создаем заголовок
	header := &protocol.PacketHeader{
		Version:     protocol.ProtocolVersion,
		Type:        protocol.PacketTypeData,
		SequenceNum: client.SequenceNum,
		PayloadSize: uint32(len(encrypted)),
	}

	// Увеличиваем sequence number
	client.SequenceNum++

	// Формируем полный пакет
	fullPacket := append(header.Marshal(), encrypted...)

	// Отправляем пакет
	_, err := s.udpConn.WriteToUDP(fullPacket, client.UDPAddr)
	return err
}

func (s *Server) handleEncryptedPacket(client *Client, header *protocol.PacketHeader, encryptedData []byte) error {
	// Создаем nonce из ClientNonce и SequenceNum
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, client.ClientNonce[:])
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], header.SequenceNum)

	// Расшифровываем данные
	decrypted, err := client.AEAD.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return err
	}

	// Пишем расшифрованный пакет в TUN интерфейс
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

	// Начинаем с первого доступного адреса в сети
	ip := make(net.IP, len(p.network.IP))
	copy(ip, p.network.IP)

	// Перебираем адреса, пока не найдем свободный
	for {
		if !p.used[ip.String()] {
			p.used[ip.String()] = true
			return ip, nil
		}

		// Увеличиваем IP на 1
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] != 0 {
				break
			}
		}

		// Проверяем, что адрес все еще в нашей сети
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
	log.Printf("Setting up routing for %s...", cfg.Interface)

	// Получаем имя основного сетевого интерфейса
	defaultIface, err := getDefaultInterface()
	if err != nil {
		log.Printf("Warning: failed to get default interface automatically: %v", err)
		// Пытаемся получить имя интерфейса из окружения
		defaultIface = os.Getenv("VPN_DEFAULT_IFACE")
		if defaultIface == "" {
			// Проверяем наличие конкретных интерфейсов
			for _, iface := range []string{"eth0", "en0", "ens33", "enp0s3"} {
				if _, err := net.InterfaceByName(iface); err == nil {
					defaultIface = iface
					break
				}
			}
			if defaultIface == "" {
				return fmt.Errorf("no network interface found and VPN_DEFAULT_IFACE not set")
			}
		}
	}

	log.Printf("Using network interface: %s", defaultIface)

	// Включаем IP forwarding
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		log.Printf("Warning: failed to enable IP forwarding: %v", err)
	}

	// Настраиваем NAT
	natRule := []string{"-t", "nat", "-A", "POSTROUTING", "-s", cfg.CIDR, "-o", defaultIface, "-j", "MASQUERADE"}
	cmd := exec.Command("iptables", natRule...)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to setup NAT, trying alternative method: %v, output: %s", err, output)
		// Пробуем альтернативный метод NAT
		natRule = []string{"-t", "nat", "-A", "POSTROUTING", "-s", cfg.CIDR, "-j", "MASQUERADE"}
		cmd = exec.Command("iptables", natRule...)
		if output, err = cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to setup NAT: %v, output: %s", err, output)
		}
	}

	// Разрешаем форвардинг
	forwardRules := [][]string{
		{"-A", "FORWARD", "-i", cfg.Interface, "-j", "ACCEPT"},
		{"-A", "FORWARD", "-o", cfg.Interface, "-j", "ACCEPT"},
	}

	for _, rule := range forwardRules {
		cmd = exec.Command("iptables", rule...)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Warning: failed to add forward rule: %v, output: %s", err, output)
			// Продолжаем выполнение, так как некоторые правила могут уже существовать
		}
	}

	// Добавляем маршрут
	cmd = exec.Command("ip", "route", "add", cfg.CIDR, "dev", cfg.Interface)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to add route, trying replacement: %v, output: %s", err, output)
		// Пробуем заменить существующий маршрут
		cmd = exec.Command("ip", "route", "replace", cfg.CIDR, "dev", cfg.Interface)
		if output, err = cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to setup route: %v, output: %s", err, output)
		}
	}

	return nil
}

func getDefaultInterface() (string, error) {
	// Пробуем несколько способов найти интерфейс по умолчанию

	// Способ 1: через ip route
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

	// Способ 2: проверяем популярные интерфейсы
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

		// Проверяем, есть ли у интерфейса IP адрес
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				return ifname, nil
			}
		}
	}

	// Способ 3: перебираем все интерфейсы
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %v", err)
	}

	for _, iface := range interfaces {
		// Пропускаем loopback и интерфейсы без флага up
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

func (s *Server) setupDarwinRouting(cfg *TunnelConfig) error {
	// Включаем IP forwarding
	if err := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	// Настраиваем NAT с помощью pfctl
	pf := fmt.Sprintf(`
nat on en0 from %s to any -> (en0)
pass in on %s all
pass out on %s all
    `, cfg.CIDR, cfg.Interface, cfg.Interface)

	// Записываем правила в временный файл
	tmpfile, err := os.CreateTemp("", "pf.conf")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(pf); err != nil {
		return fmt.Errorf("failed to write pf rules: %v", err)
	}

	// Загружаем правила
	if err := exec.Command("pfctl", "-f", tmpfile.Name()).Run(); err != nil {
		return fmt.Errorf("failed to load pf rules: %v", err)
	}

	// Включаем PF
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
	// Удаляем правила NAT
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", cfg.CIDR, "-j", "MASQUERADE").Run()

	// Удаляем правила форвардинга
	exec.Command("iptables", "-D", "FORWARD", "-i", cfg.Interface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-o", cfg.Interface, "-j", "ACCEPT").Run()

	return nil
}

func (s *Server) cleanupDarwinRouting(cfg *TunnelConfig) error {
	// Отключаем PF
	exec.Command("pfctl", "-d").Run()

	return nil
}

// cleanupOldConfig очищает старые настройки VPN
func cleanupOldConfig(interfaceName string, cidr string) error {
	log.Printf("Cleaning up old VPN configuration...")

	// Останавливаем systemd-networkd
	if err := exec.Command("systemctl", "stop", "systemd-networkd").Run(); err != nil {
		log.Printf("Warning: failed to stop systemd-networkd: %v", err)
	}

	// Удаляем старый интерфейс
	cleanupInterface(interfaceName)

	// Ждем немного после удаления интерфейса
	time.Sleep(time.Second * 2)

	// Очищаем правила iptables
	cleanupIPTables(interfaceName, cidr)

	// Очищаем маршруты
	cleanupRoutes(interfaceName, cidr)

	return nil
}

// cleanupIPTables очищает правила iptables
func cleanupIPTables(interfaceName string, cidr string) {
	// Получаем основной интерфейс
	defaultIface, err := getDefaultInterface()
	if err != nil {
		log.Printf("Warning: couldn't get default interface: %v", err)
		defaultIface = "*" // Используем wildcard если не можем получить интерфейс
	}

	rules := [][]string{
		{"iptables", "-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-o", defaultIface, "-j", "MASQUERADE"},
		{"iptables", "-D", "FORWARD", "-i", interfaceName, "-j", "ACCEPT"},
		{"iptables", "-D", "FORWARD", "-o", interfaceName, "-j", "ACCEPT"},
	}

	for _, rule := range rules {
		// Пытаемся удалить правило несколько раз, так как их может быть несколько
		for i := 0; i < 5; i++ {
			cmd := exec.Command(rule[0], rule[1:]...)
			if _, err := cmd.CombinedOutput(); err != nil {
				break // Правило больше не существует
			}
			log.Printf("Removed iptables rule: %v", rule)
		}
	}
}

// cleanupRoutes очищает маршруты
func cleanupRoutes(interfaceName string, cidr string) {
	// Удаляем все маршруты для интерфейса
	cmd := exec.Command("ip", "route", "flush", "dev", interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: couldn't flush routes: %v, output: %s", err, string(output))
	}

	// Дополнительно пытаемся удалить конкретный маршрут
	cmd = exec.Command("ip", "route", "del", cidr, "dev", interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: couldn't delete specific route: %v, output: %s", err, string(output))
	}
}

// cleanupInterface удаляет старый интерфейс
func cleanupInterface(interfaceName string) {
	cmd := exec.Command("ip", "link", "delete", interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: couldn't delete interface %s: %v, output: %s",
			interfaceName, err, output)
	} else {
		log.Printf("Removed interface: %s", interfaceName)
	}
}
