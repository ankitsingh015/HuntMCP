package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
	"github.com/ankitsingh015/HuntMCP/backend/internal/repository"
)

type HuntHandler struct {
	repo *repository.HuntRepository
}

func NewHuntHandler(repo *repository.HuntRepository) *HuntHandler {
	return &HuntHandler{repo: repo}
}

func (h *HuntHandler) Save(c *gin.Context) {
	var req model.HuntSaveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error:   "invalid request",
			Details: err.Error(),
		})
		return
	}

	hunt, err := h.repo.Save(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error:   "failed to save hunt",
			Details: err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, hunt)
}

func (h *HuntHandler) Recall(c *gin.Context) {
	target := c.Query("target")
	if target == "" {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: "target query parameter is required",
		})
		return
	}

	hunt, err := h.repo.Recall(target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error:   "failed to recall hunt",
			Details: err.Error(),
		})
		return
	}

	if hunt == nil {
		c.JSON(http.StatusOK, model.HuntRecallResponse{
			Hunt:   nil,
			Status: "no previous hunt found for this target",
		})
		return
	}

	c.JSON(http.StatusOK, model.HuntRecallResponse{
		Hunt:   hunt,
		Status: "previous hunt found",
	})
}

func (h *HuntHandler) ListByUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	uid, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{
			Error: "user not authenticated",
		})
		return
	}

	hunts, err := h.repo.ListByUser(uid, 20)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error:   "failed to list hunts",
			Details: err.Error(),
		})
		return
	}

	if hunts == nil {
		hunts = []model.Hunt{}
	}
	c.JSON(http.StatusOK, gin.H{"hunts": hunts, "total": len(hunts)})
}

func (h *HuntHandler) SearchByTech(c *gin.Context) {
	var req struct {
		Techs []string `json:"techs" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error:   "techs array is required",
			Details: err.Error(),
		})
		return
	}

	hunts, err := h.repo.SearchByTech(req.Techs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error:   "failed to search hunts",
			Details: err.Error(),
		})
		return
	}

	if hunts == nil {
		hunts = []model.Hunt{}
	}
	c.JSON(http.StatusOK, gin.H{"hunts": hunts, "total": len(hunts)})
}

func (h *HuntHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.repo.Delete(id); err != nil {
		c.JSON(http.StatusNotFound, model.ErrorResponse{
			Error: "hunt not found",
		})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

func (h *HuntHandler) Stats(c *gin.Context) {
	stats, err := h.repo.Stats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error:   "failed to get stats",
			Details: err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, stats)
}
