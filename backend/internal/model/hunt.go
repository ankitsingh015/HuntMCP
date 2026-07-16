package model

import "time"

type Hunt struct {
	ID            string    `json:"id"`
	Target        string    `json:"target"`
	TechStack     []string  `json:"tech_stack,omitempty"`
	Findings      []Finding `json:"findings,omitempty"`
	Chains        []Chain   `json:"chains,omitempty"`
	Subdomains    []string  `json:"subdomains,omitempty"`
	BountyEstimate string   `json:"bounty_estimate,omitempty"`
	Summary       string    `json:"summary,omitempty"`
	HuntedAt      time.Time `json:"hunted_at"`
	UserID        string    `json:"user_id,omitempty"`
}

type Finding struct {
	Class    string `json:"class"`
	Endpoint string `json:"endpoint"`
	Severity string `json:"severity"`
	Tool     string `json:"tool"`
	Payload  string `json:"payload,omitempty"`
}

type Chain struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Steps       []string `json:"steps"`
	Outcome     string   `json:"outcome"`
}

type HuntSaveRequest struct {
	Target         string    `json:"target" binding:"required"`
	TechStack      []string  `json:"tech_stack"`
	Findings       []Finding `json:"findings"`
	Chains         []Chain   `json:"chains"`
	Subdomains     []string  `json:"subdomains"`
	BountyEstimate string    `json:"bounty_estimate"`
	Summary        string    `json:"summary"`
}

type HuntRecallResponse struct {
	Hunt   *Hunt  `json:"hunt"`
	Status string `json:"status"`
}
