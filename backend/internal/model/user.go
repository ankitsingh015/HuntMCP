package model

import "time"

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type UserCreateRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

type HealthResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	DB        string `json:"database"`
}
