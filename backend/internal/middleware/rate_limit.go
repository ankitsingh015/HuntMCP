package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
)

type visitor struct {
	count    int
	lastSeen time.Time
}

type RateLimiter struct {
	mu       sync.RWMutex
	visitors map[string]*visitor
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, v := range rl.visitors {
			if now.Sub(v.lastSeen) > rl.window*2 {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		rl.mu.Lock()
		v, exists := rl.visitors[ip]
		now := time.Now()

		if !exists || now.Sub(v.lastSeen) > rl.window {
			rl.visitors[ip] = &visitor{count: 1, lastSeen: now}
			rl.mu.Unlock()
			c.Next()
			return
		}

		v.count++
		v.lastSeen = now

		if v.count > rl.limit {
			rl.mu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, model.ErrorResponse{
				Error:   "rate limit exceeded",
				Details: "max 100 requests per minute",
			})
			return
		}
		rl.mu.Unlock()
		c.Next()
	}
}

func NewDefaultRateLimiter() *RateLimiter {
	return NewRateLimiter(100, 1*time.Minute)
}
