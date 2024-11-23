package main

import (
	"flag"
	"github.com/neokofg/go-pet-vpn-server/internal/server"
	"github.com/neokofg/go-pet-vpn-server/internal/server/config"
	"github.com/neokofg/go-pet-vpn-server/internal/server/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	if err := server.CheckRootPrivileges(); err != nil {
		log.Fatalf("Error: %v\nPlease run this program with sudo", err)
	}
	// Парсим аргументы командной строки
	tcpAddr := flag.String("tcp", ":8000", "TCP address to listen on")
	udpAddr := flag.String("udp", ":8001", "UDP address to listen on")
	dbPath := flag.String("db", "vpn.db", "Path to SQLite database")
	tunName := flag.String("tun", "tun0", "TUN interface name")
	vpnCIDR := flag.String("cidr", "10.0.0.0/24", "VPN network CIDR")
	flag.Parse()

	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
			log.Fatal("Error: TUN/TAP driver not available. Please install it:\n" +
				"For Ubuntu/Debian: sudo apt-get install linux-modules-extra-$(uname -r)\n" +
				"For CentOS/RHEL: sudo yum install kernel-devel\n" +
				"After installation, run: sudo modprobe tun")
		}
	}

	// Инициализируем базу данных
	db, err := gorm.Open(sqlite.Open(*dbPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Автоматическая миграция схемы
	if err := models.InitDB(db); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Создаем конфигурацию сервера
	cfg := &config.Config{
		TCPAddr:      *tcpAddr,
		UDPAddr:      *udpAddr,
		DatabasePath: *dbPath,
	}

	// Конфигурация туннеля
	tunCfg := &server.TunnelConfig{
		Interface: *tunName,
		CIDR:      *vpnCIDR,
		MTU:       1500,
	}

	// Создаем сервер
	srv, err := server.NewServer(cfg, db)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Обработка сигналов для graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal: %v", sig)
		srv.Stop()
	}()

	// Запускаем сервер
	log.Printf("Starting VPN server...")
	if err := srv.Start(tunCfg); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
