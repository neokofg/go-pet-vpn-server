package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
	"strings"
	"time"
)

type Token struct {
	ID        uint   `gorm:"primarykey"`
	UserID    uint   `gorm:"not null"`
	Token     string `gorm:"uniqueIndex;size:64;not null"`
	CreatedAt time.Time
	ExpiresAt time.Time
	Active    bool `gorm:"default:true"`
}

func main() {
	// Определяем флаги
	dbPath := flag.String("db", "vpn.db", "Path to SQLite database")
	action := flag.String("action", "", "Action to perform: create, list, revoke")
	userID := flag.Uint("user", 0, "User ID for token creation")
	tokenStr := flag.String("token", "", "Token string for revocation")
	days := flag.Int("days", 30, "Token validity period in days")
	flag.Parse()

	// Проверяем обязательные параметры
	if *action == "" {
		log.Fatal("Action is required. Use -action [create|list|revoke]")
	}

	// Подключаемся к базе данных
	db, err := gorm.Open(sqlite.Open(*dbPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Автомиграция схемы
	if err := db.AutoMigrate(&Token{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Выполняем действие
	switch *action {
	case "create":
		if *userID == 0 {
			log.Fatal("User ID is required for token creation")
		}
		token, err := createToken(db, *userID, *days)
		if err != nil {
			log.Fatalf("Failed to create token: %v", err)
		}
		fmt.Printf("Created token: %s\n", token)

	case "list":
		if err := listTokens(db); err != nil {
			log.Fatalf("Failed to list tokens: %v", err)
		}

	case "revoke":
		if *tokenStr == "" {
			log.Fatal("Token string is required for revocation")
		}
		if err := revokeToken(db, *tokenStr); err != nil {
			log.Fatalf("Failed to revoke token: %v", err)
		}
		fmt.Println("Token revoked successfully")

	default:
		log.Fatalf("Unknown action: %s", *action)
	}
}

func createToken(db *gorm.DB, userID uint, days int) (string, error) {
	// Генерируем случайный токен
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %v", err)
	}
	tokenStr := hex.EncodeToString(tokenBytes)

	// Создаем запись в базе
	token := &Token{
		UserID:    userID,
		Token:     tokenStr,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().AddDate(0, 0, days),
		Active:    true,
	}

	if err := db.Create(token).Error; err != nil {
		return "", fmt.Errorf("failed to save token: %v", err)
	}

	return tokenStr, nil
}

func listTokens(db *gorm.DB) error {
	var tokens []Token
	if err := db.Find(&tokens).Error; err != nil {
		return err
	}

	fmt.Printf("%-8s %-8s %-64s %-20s %-20s %-8s\n",
		"ID", "USER_ID", "TOKEN", "CREATED", "EXPIRES", "ACTIVE")
	fmt.Println(strings.Repeat("-", 130))

	for _, t := range tokens {
		fmt.Printf("%-8d %-8d %-64s %-20s %-20s %-8v\n",
			t.ID, t.UserID, t.Token,
			t.CreatedAt.Format("2006-01-02 15:04:05"),
			t.ExpiresAt.Format("2006-01-02 15:04:05"),
			t.Active)
	}

	return nil
}

func revokeToken(db *gorm.DB, tokenStr string) error {
	result := db.Model(&Token{}).
		Where("token = ?", tokenStr).
		Update("active", false)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("token not found")
	}

	return nil
}
