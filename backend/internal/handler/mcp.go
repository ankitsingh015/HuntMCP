package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
	"github.com/ankitsingh015/HuntMCP/backend/internal/repository"
)

type MCPHandler struct {
	writeupRepo *repository.WriteupRepository
	huntRepo    *repository.HuntRepository
}

func NewMCPHandler(writeupRepo *repository.WriteupRepository, huntRepo *repository.HuntRepository) *MCPHandler {
	return &MCPHandler{writeupRepo: writeupRepo, huntRepo: huntRepo}
}

type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type MCPToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (h *MCPHandler) ServeMCP(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, MCPResponse{
			JSONRPC: "2.0",
			Error:   &MCPError{Code: -32700, Message: "Parse error"},
		})
		return
	}

	var req MCPRequest
	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, MCPResponse{
			JSONRPC: "2.0",
			Error:   &MCPError{Code: -32700, Message: "Parse error"},
		})
		return
	}

	switch req.Method {
	case "initialize":
		c.JSON(http.StatusOK, MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"protocolVersion": "0.1.0",
				"serverInfo": map[string]string{
					"name":    "huntmcp-backend",
					"version": "0.1.0",
				},
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{
						"query_rag":   map[string]string{"description": "Query writeup RAG database"},
						"save_hunt":   map[string]string{"description": "Save hunt results"},
						"recall_hunt": map[string]string{"description": "Recall past hunt"},
					},
				},
			},
		})

	case "tools/call":
		var tc MCPToolCall
		if err := json.Unmarshal(req.Params, &tc); err != nil {
			c.JSON(http.StatusBadRequest, MCPResponse{
				JSONRPC: "2.0", ID: req.ID,
				Error: &MCPError{Code: -32602, Message: "Invalid params"},
			})
			return
		}

		switch tc.Name {
		case "query_rag":
			var params struct {
				Query string  `json:"query"`
				TopK  int     `json:"top_k"`
				Score float64 `json:"score"`
			}
			json.Unmarshal(tc.Arguments, &params)
			if params.TopK <= 0 {
				params.TopK = 5
			}
			if params.Score <= 0 {
				params.Score = 0.5
			}
			results, err := h.writeupRepo.VectorSearch(nil, params.TopK, params.Score)
			if err != nil {
				c.JSON(http.StatusOK, MCPResponse{
					JSONRPC: "2.0", ID: req.ID,
					Result: map[string]interface{}{
						"results": []interface{}{},
						"error":   err.Error(),
					},
				})
				return
			}
			c.JSON(http.StatusOK, MCPResponse{
				JSONRPC: "2.0", ID: req.ID,
				Result: map[string]interface{}{
					"results": results,
					"count":   len(results),
				},
			})

		case "save_hunt":
			var params model.HuntSaveRequest
			if err := json.Unmarshal(tc.Arguments, &params); err != nil {
				c.JSON(http.StatusOK, MCPResponse{
					JSONRPC: "2.0", ID: req.ID,
					Error: &MCPError{Code: -32602, Message: "Invalid hunt params"},
				})
				return
			}
			hunt, err := h.huntRepo.Save(params)
			if err != nil {
				c.JSON(http.StatusOK, MCPResponse{
					JSONRPC: "2.0", ID: req.ID,
					Error: &MCPError{Code: -32603, Message: err.Error()},
				})
				return
			}
			c.JSON(http.StatusOK, MCPResponse{
				JSONRPC: "2.0", ID: req.ID,
				Result: hunt,
			})

		case "recall_hunt":
			var params struct {
				Target string `json:"target"`
			}
			json.Unmarshal(tc.Arguments, &params)
			hunt, err := h.huntRepo.Recall(params.Target)
			if err != nil {
				c.JSON(http.StatusOK, MCPResponse{
					JSONRPC: "2.0", ID: req.ID,
					Result: map[string]interface{}{"hunt": nil, "status": err.Error()},
				})
				return
			}
			if hunt == nil {
				c.JSON(http.StatusOK, MCPResponse{
					JSONRPC: "2.0", ID: req.ID,
					Result: map[string]interface{}{"hunt": nil, "status": "not found"},
				})
				return
			}
			c.JSON(http.StatusOK, MCPResponse{
				JSONRPC: "2.0", ID: req.ID,
				Result: map[string]interface{}{"hunt": *hunt, "status": "found"},
			})

		default:
			c.JSON(http.StatusOK, MCPResponse{
				JSONRPC: "2.0", ID: req.ID,
				Error: &MCPError{Code: -32601, Message: "Method not found: " + tc.Name},
			})
		}

	default:
		c.JSON(http.StatusOK, MCPResponse{
			JSONRPC: "2.0", ID: req.ID,
			Error: &MCPError{Code: -32601, Message: "Method not found: " + req.Method},
		})
	}
}
