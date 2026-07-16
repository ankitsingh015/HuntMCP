package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
	"github.com/ankitsingh015/HuntMCP/backend/internal/repository"
)

type HealthHandler struct {
	db *repository.DB
}

func NewHealthHandler(db *repository.DB) *HealthHandler {
	return &HealthHandler{db: db}
}

func (h *HealthHandler) Health(c *gin.Context) {
	dbStatus := "ok"
	if err := h.db.Ping(); err != nil {
		dbStatus = "error: " + err.Error()
	}

	c.JSON(http.StatusOK, model.HealthResponse{
		Status:    "ok",
		Version:   "0.1.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		DB:        dbStatus,
	})
}
