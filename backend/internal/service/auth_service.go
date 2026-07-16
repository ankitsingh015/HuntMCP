package service

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
	"github.com/ankitsingh015/HuntMCP/backend/internal/repository"
)

type AuthService struct {
	db *repository.DB
}

func NewAuthService(db *repository.DB) *AuthService {
	return &AuthService{db: db}
}

func (s *AuthService) getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "huntmcp-dev-secret-change-in-production"
	}
	return []byte(secret)
}

func (s *AuthService) Register(req model.UserCreateRequest) (model.AuthResponse, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return model.AuthResponse{}, fmt.Errorf("hash password: %w", err)
	}

	var id string
	err = s.db.QueryRow(
		`INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3)
		 RETURNING id`,
		req.Email, req.Username, string(hash),
	).Scan(&id)
	if err != nil {
		return model.AuthResponse{}, fmt.Errorf("create user: %w", err)
	}

	user := model.User{
		ID:       id,
		Email:    req.Email,
		Username: req.Username,
		Role:     "user",
		CreatedAt: time.Now(),
	}

	token, err := s.generateToken(user)
	if err != nil {
		return model.AuthResponse{}, err
	}

	return model.AuthResponse{Token: token, User: user}, nil
}

func (s *AuthService) Login(req model.LoginRequest) (model.AuthResponse, error) {
	var user model.User
	var hash string

	err := s.db.QueryRow(
		`SELECT id, email, username, role, password_hash, created_at
		 FROM users WHERE email = $1`, req.Email,
	).Scan(&user.ID, &user.Email, &user.Username, &user.Role, &hash, &user.CreatedAt)
	if err == sql.ErrNoRows {
		return model.AuthResponse{}, fmt.Errorf("invalid email or password")
	}
	if err != nil {
		return model.AuthResponse{}, fmt.Errorf("query user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		return model.AuthResponse{}, fmt.Errorf("invalid email or password")
	}

	token, err := s.generateToken(user)
	if err != nil {
		return model.AuthResponse{}, err
	}

	return model.AuthResponse{Token: token, User: user}, nil
}

func (s *AuthService) ValidateToken(tokenString string) (*model.Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.getJWTSecret(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return &model.Claims{
		UserID:   claims["user_id"].(string),
		Username: claims["username"].(string),
		Role:     claims["role"].(string),
	}, nil
}

func (s *AuthService) generateToken(user model.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(72 * time.Hour).Unix(),
		"iat":      time.Now().Unix(),
		"jti":      generateJTI(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.getJWTSecret())
}

func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
