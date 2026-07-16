package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
	"github.com/ankitsingh015/HuntMCP/backend/internal/repository"
)

type WriteupHandler struct {
	repo *repository.WriteupRepository
}

func NewWriteupHandler(repo *repository.WriteupRepository) *WriteupHandler {
	return &WriteupHandler{repo: repo}
}

func (h *WriteupHandler) Create(c *gin.Context) {
	var req model.WriteupCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error:   "invalid request",
			Details: err.Error(),
		})
		return
	}

	writeup, err := h.repo.Create(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error:   "failed to create writeup",
			Details: err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, writeup)
}

func (h *WriteupHandler) GetByID(c *gin.Context) {
	id := c.Param("id")
	writeup, err := h.repo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, model.ErrorResponse{
			Error: "writeup not found",
		})
		return
	}
	c.JSON(http.StatusOK, writeup)
}

func (h *WriteupHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	vulnClass := c.Query("vuln_class")
	tech := c.Query("tech")
	search := c.Query("search")

	result, err := h.repo.List(page, perPage, vulnClass, tech, search)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error:   "failed to list writeups",
			Details: err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *WriteupHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req model.WriteupUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error:   "invalid request",
			Details: err.Error(),
		})
		return
	}

	writeup, err := h.repo.Update(id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error:   "failed to update writeup",
			Details: err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, writeup)
}

func (h *WriteupHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.repo.Delete(id); err != nil {
		c.JSON(http.StatusNotFound, model.ErrorResponse{
			Error: "writeup not found",
		})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

func (h *WriteupHandler) QueryRAG(c *gin.Context) {
	var req model.RAGQueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error:   "invalid request",
			Details: err.Error(),
		})
		return
	}

	if req.TopK <= 0 || req.TopK > 50 {
		req.TopK = 10
	}
	if req.Score <= 0 {
		req.Score = 0.5
	}

	results, err := h.repo.VectorSearch(nil, req.TopK, req.Score)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error:   "RAG query failed",
			Details: "Vector search requires embedded writeups. Use POST /api/v1/reindex first.",
		})
		return
	}

	c.JSON(http.StatusOK, model.RAGQueryResponse{
		Results: results,
		Query:   req.Query,
	})
}

func (h *WriteupHandler) BatchCreate(c *gin.Context) {
	var reqs []model.WriteupCreateRequest
	if err := c.ShouldBindJSON(&reqs); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error:   "invalid request body (expected array)",
			Details: err.Error(),
		})
		return
	}

	count, err := h.repo.BatchCreate(reqs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Error:   "batch create failed",
			Details: err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"created": count})
}
