package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
	"github.com/ankitsingh015/HuntMCP/backend/internal/service"
)

func AuthMiddleware(authService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{
				Error: "missing authorization header",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{
				Error: "invalid authorization format (expected: Bearer <token>)",
			})
			return
		}

		claims, err := authService.ValidateToken(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{
				Error:   "invalid or expired token",
				Details: err.Error(),
			})
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}

func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists || role.(string) != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, model.ErrorResponse{
				Error: "admin access required",
			})
			return
		}
		c.Next()
	}
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
