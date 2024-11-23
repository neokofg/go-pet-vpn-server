package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	Username  string  `gorm:"unique;not null"`
	Password  string  `gorm:"not null"` // Хранить только хэш
	Tokens    []Token `gorm:"foreignKey:UserID"`
}

type Token struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	UserID    uint   `gorm:"not null"`
	Token     string `gorm:"unique;not null"`
	LastUsed  time.Time
	ExpiresAt time.Time
}

// GenerateToken создает новый токен для пользователя
func GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateToken создает новый токен для пользователя
func CreateToken(db *gorm.DB, userID uint) (*Token, error) {
	tokenStr, err := GenerateToken(32) // 64 символа в hex
	if err != nil {
		return nil, err
	}

	token := &Token{
		UserID:    userID,
		Token:     tokenStr,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 дней
	}

	if err := db.Create(token).Error; err != nil {
		return nil, err
	}

	return token, nil
}

// ValidateToken проверяет валидность токена
func ValidateToken(db *gorm.DB, tokenStr string) (*Token, error) {
	var token Token
	if err := db.Where("token = ? AND expires_at > ?", tokenStr, time.Now()).First(&token).Error; err != nil {
		return nil, err
	}

	// Обновляем время последнего использования
	token.LastUsed = time.Now()
	db.Save(&token)

	return &token, nil
}

// InitDB инициализирует базу данных
func InitDB(db *gorm.DB) error {
	return db.AutoMigrate(&User{}, &Token{})
}
