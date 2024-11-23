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
	"sync"
	"time"
)

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
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return errors.New("invalid IP packet")
	}

	// Проверяем, что IP назначения соответствует нашей VPN сети
	dstIP := net.IP(packet[16:20])
	if !tun.config.Network.Contains(dstIP) {
		return fmt.Errorf("destination IP %s not in VPN network", dstIP)
	}

	// Записываем пакет в TUN интерфейс
	if _, err := tun.Write(packet); err != nil {
		return fmt.Errorf("error writing to TUN: %v", err)
	}

	return nil
}

type Server struct {
	cfg          *config.Config
	db           *gorm.DB
	tcpListener  net.Listener
	udpConn      *net.UDPConn
	clients      map[string]*Client // ключ - токен
	clientsMutex sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	tunInterface *TUNDevice
	ipPool       *IPPool
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
	// Инициализируем IP пул
	ipPool, err := NewIPPool(tunCfg.CIDR)
	if err != nil {
		return fmt.Errorf("failed to create IP pool: %v", err)
	}
	s.ipPool = ipPool

	// Создаем и настраиваем TUN интерфейс
	tunInterface, err := s.setupTunnel(tunCfg)
	if err != nil {
		return fmt.Errorf("failed to setup TUN interface: %v", err)
	}
	s.tunInterface = tunInterface

	// Настраиваем маршрутизацию
	if err := s.setupRouting(tunCfg); err != nil {
		s.cleanupRouting(tunCfg)
		return fmt.Errorf("failed to setup routing: %v", err)
	}

	// Запускаем обработку TCP подключений
	go s.handleTCPConnections()

	// Запускаем обработку UDP пакетов
	go s.handleUDPPackets()

	// Запускаем обработку TUN интерфейса
	go s.handleTunToUDP(tunInterface)

	// Запускаем очистку неактивных клиентов
	go s.cleanupInactiveClients()

	log.Printf("Server started. TCP: %s, UDP: %s, TUN: %s",
		s.cfg.TCPAddr, s.cfg.UDPAddr, tunInterface.Name)

	<-s.ctx.Done()

	// Очищаем настройки при остановке
	s.cleanupRouting(tunCfg)
	return nil
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

func (s *Server) handleTCPConnections() {
	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return // Сервер остановлен
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
	}

	ctx, cancel := context.WithCancel(s.ctx)
	client.Ctx = ctx
	client.Cancel = cancel

	// Добавляем клиента в map
	s.clientsMutex.Lock()
	s.clients[token.Token] = client
	s.clientsMutex.Unlock()

	// Отправляем ответ на handshake
	response := &protocol.HandshakeResponse{
		ServerNonce: serverNonce,
		Key:         [32]byte(key),
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
	_, err = conn.Write(append(headerData, responseData...))
	if err != nil {
		log.Printf("Error sending handshake response: %v", err)
		return
	}

	// Снимаем таймаут после успешного хендшейка
	conn.SetDeadline(time.Time{})

	log.Printf("Client connected: %s", token.Token)
}

func (s *Server) handleUDPPackets() {
	buf := make([]byte, protocol.MaxPacketSize)
	for {
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return // Сервер остановлен
			}
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}

		go s.handleUDPPacket(buf[:n], addr)
	}
}

func (s *Server) handleUDPPacket(data []byte, addr *net.UDPAddr) {
	if len(data) < protocol.HeaderSize {
		return
	}

	header, err := protocol.UnmarshalHeader(data[:protocol.HeaderSize])
	if err != nil {
		log.Printf("Error parsing UDP header: %v", err)
		return
	}

	// Ищем клиента по sequence number и адресу
	s.clientsMutex.RLock()
	var targetClient *Client
	for _, client := range s.clients {
		if client.UDPAddr != nil && client.UDPAddr.String() == addr.String() {
			targetClient = client
			break
		}
	}
	s.clientsMutex.RUnlock()

	if targetClient == nil {
		log.Printf("Unknown client from %s", addr.String())
		return
	}

	targetClient.Lock()
	defer targetClient.Unlock()

	// Обновляем время последнего пакета
	targetClient.LastSeen = time.Now()

	switch header.Type {
	case protocol.PacketTypeData:
		// Расшифровываем данные
		nonce := make([]byte, chacha20poly1305.NonceSize)
		copy(nonce, targetClient.ClientNonce[:])
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], header.SequenceNum)

		payload, err := targetClient.AEAD.Open(nil, nonce, data[protocol.HeaderSize:], nil)
		if err != nil {
			log.Printf("Error decrypting payload: %v", err)
			return
		}

		if err := targetClient.WriteTUN(s.tunInterface, payload); err != nil {
			log.Printf("Error writing to TUN: %v", err)
			return
		}

	case protocol.PacketTypeKeepalive:
		// Просто обновляем LastSeen

	case protocol.PacketTypeDisconnect:
		targetClient.Cancel()
		s.clientsMutex.Lock()
		delete(s.clients, targetClient.Token)
		s.clientsMutex.Unlock()
		log.Printf("Client disconnected: %s", targetClient.Token)
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
	// Создаем TUN интерфейс
	cfg := water.Config{
		DeviceType: water.TUN,
	}

	// В Linux можно задать имя интерфейса
	if runtime.GOOS == "linux" {
		cfg.Name = config.Name
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

	// Настраиваем интерфейс
	if err := tun.configure(); err != nil {
		tun.Close()
		return nil, err
	}

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
	// Поднимаем интерфейс
	if err := exec.Command("ip", "link", "set", "dev", t.name, "up").Run(); err != nil {
		return fmt.Errorf("failed to up interface: %v", err)
	}

	// Устанавливаем MTU
	if err := exec.Command("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", t.config.MTU)).Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	// Назначаем IP адрес
	addr := fmt.Sprintf("%s/%d", t.config.Address.String(), maskBits(t.config.Network.Mask))
	if err := exec.Command("ip", "addr", "add", addr, "dev", t.name).Run(); err != nil {
		return fmt.Errorf("failed to set address: %v", err)
	}

	// Добавляем маршруты
	for _, route := range t.config.Routes {
		args := []string{"route", "add", route.Network.String()}
		if route.Gateway != nil {
			args = append(args, "via", route.Gateway.String())
		}
		args = append(args, "dev", t.name)

		if err := exec.Command("ip", args...).Run(); err != nil {
			return fmt.Errorf("failed to add route: %v", err)
		}
	}

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

const (
	TUN_MTU = 1500
)

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

	// Создаем IP пул для клиентов (исключая адрес сервера)
	s.ipPool, err = NewIPPool(cfg.CIDR)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("failed to create IP pool: %v", err)
	}
	// Резервируем первый адрес для сервера
	s.ipPool.Reserve(serverIP)

	// Настраиваем маршрутизацию
	if err := s.setupRouting(cfg); err != nil {
		tun.Close()
		return nil, fmt.Errorf("failed to setup routing: %v", err)
	}

	log.Printf("TUN interface %s configured with IP %s", tun.name, serverIP)
	return tun, nil
}

func (s *Server) handleTunToUDP(tun *TUNDevice) {
	defer tun.Close()

	for {
		// Читаем пакет из TUN
		packet, err := tun.ReadPacket()
		if err != nil {
			if s.ctx.Err() != nil {
				return // Сервер остановлен
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
			if client.AssignedIP.Equal(dstIP) {
				targetClient = client
				break
			}
		}
		s.clientsMutex.RUnlock()

		if targetClient == nil {
			continue // Неизвестный получатель
		}

		targetClient.Lock()

		// Создаем nonce для шифрования
		nonce := make([]byte, chacha20poly1305.NonceSize)
		copy(nonce, targetClient.ServerNonce[:])
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], targetClient.SequenceNum)

		// Шифруем пакет
		encrypted := targetClient.AEAD.Seal(nil, nonce, packet, nil)

		// Создаем заголовок
		header := &protocol.PacketHeader{
			Version:     protocol.ProtocolVersion,
			Type:        protocol.PacketTypeData,
			SequenceNum: targetClient.SequenceNum,
			PayloadSize: uint32(len(encrypted)),
		}

		// Увеличиваем sequence number
		targetClient.SequenceNum++

		// Формируем полный пакет
		fullPacket := append(header.Marshal(), encrypted...)

		targetClient.Unlock()

		// Отправляем пакет клиенту
		if targetClient.UDPAddr != nil {
			if _, err := s.udpConn.WriteToUDP(fullPacket, targetClient.UDPAddr); err != nil {
				log.Printf("Error sending packet to client %s: %v", targetClient.AssignedIP, err)
			}
		}
	}
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
	// Включаем IP forwarding
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	// Настраиваем NAT
	if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", cfg.CIDR, "-j", "MASQUERADE").Run(); err != nil {
		return fmt.Errorf("failed to setup NAT: %v", err)
	}

	// Разрешаем форвардинг для VPN трафика
	if err := exec.Command("iptables", "-A", "FORWARD", "-i", cfg.Interface, "-j", "ACCEPT").Run(); err != nil {
		return fmt.Errorf("failed to allow forwarding: %v", err)
	}

	if err := exec.Command("iptables", "-A", "FORWARD", "-o", cfg.Interface, "-j", "ACCEPT").Run(); err != nil {
		return fmt.Errorf("failed to allow forwarding: %v", err)
	}

	return nil
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
