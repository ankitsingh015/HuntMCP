package model

import "time"

type Writeup struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	URL        string    `json:"url,omitempty"`
	VulnClass  string    `json:"vuln_class"`
	TargetTech []string  `json:"target_tech,omitempty"`
	Bounty     int       `json:"bounty,omitempty"`
	Author     string    `json:"author,omitempty"`
	Content    string    `json:"content"`
	SourceType string    `json:"source_type"`
	CreatedAt  time.Time `json:"created_at"`
}

type WriteupCreateRequest struct {
	Title      string   `json:"title" binding:"required"`
	URL        string   `json:"url"`
	VulnClass  string   `json:"vuln_class" binding:"required"`
	TargetTech []string `json:"target_tech"`
	Bounty     int      `json:"bounty"`
	Author     string   `json:"author"`
	Content    string   `json:"content" binding:"required"`
}

type WriteupUpdateRequest struct {
	Title      *string  `json:"title"`
	URL        *string  `json:"url"`
	VulnClass  *string  `json:"vuln_class"`
	TargetTech []string `json:"target_tech"`
	Bounty     *int     `json:"bounty"`
	Author     *string  `json:"author"`
	Content    *string  `json:"content"`
}

type WriteupListResponse struct {
	Writeups []Writeup `json:"writeups"`
	Total    int       `json:"total"`
	Page     int       `json:"page"`
	PerPage  int       `json:"per_page"`
}

type RAGQueryRequest struct {
	Query string  `json:"query" binding:"required"`
	TopK  int     `json:"top_k"`
	Score float64 `json:"score"`
}

type RAGQueryResult struct {
	Writeup    Writeup `json:"writeup"`
	Similarity float64 `json:"similarity"`
}

type RAGQueryResponse struct {
	Results []RAGQueryResult `json:"results"`
	Query   string           `json:"query"`
}
