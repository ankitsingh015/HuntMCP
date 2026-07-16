package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
	"github.com/ankitsingh015/HuntMCP/backend/internal/service"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req model.UserCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error:   "invalid request",
			Details: err.Error(),
		})
		return
	}

	resp, err := h.authService.Register(req)
	if err != nil {
		c.JSON(http.StatusConflict, model.ErrorResponse{
			Error:   "registration failed",
			Details: err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, resp)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error:   "invalid request",
			Details: err.Error(),
		})
		return
	}

	resp, err := h.authService.Login(req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{
			Error:   "login failed",
			Details: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}
