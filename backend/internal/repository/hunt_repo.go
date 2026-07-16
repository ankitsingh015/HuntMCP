package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

type HuntRepository struct {
	db *DB
}

func NewHuntRepository(db *DB) *HuntRepository {
	return &HuntRepository{db: db}
}

type HuntRow struct {
	ID             string
	Target         string
	TechStack      []string
	FindingsJSON   string
	ChainsJSON     string
	Subdomains     []string
	BountyEstimate string
	Summary        string
	UserID         sql.NullString
	HuntedAt       time.Time
}

func scanHunt(scanner interface {
	Scan(dest ...interface{}) error
}) (model.Hunt, error) {
	var row HuntRow
	err := scanner.Scan(
		&row.ID, &row.Target, pq.Array(&row.TechStack),
		&row.FindingsJSON, &row.ChainsJSON,
		pq.Array(&row.Subdomains), &row.BountyEstimate,
		&row.Summary, &row.UserID, &row.HuntedAt,
	)
	if err != nil {
		return model.Hunt{}, err
	}

	h := model.Hunt{
		ID:             row.ID,
		Target:         row.Target,
		TechStack:      row.TechStack,
		Subdomains:     row.Subdomains,
		BountyEstimate: row.BountyEstimate,
		Summary:        row.Summary,
		HuntedAt:       row.HuntedAt,
	}

	if row.FindingsJSON != "" {
		json.Unmarshal([]byte(row.FindingsJSON), &h.Findings)
	}
	if row.ChainsJSON != "" {
		json.Unmarshal([]byte(row.ChainsJSON), &h.Chains)
	}
	if row.UserID.Valid {
		h.UserID = row.UserID.String
	}

	return h, nil
}

func (r *HuntRepository) Save(req model.HuntSaveRequest) (model.Hunt, error) {
	findingsJSON, _ := json.Marshal(req.Findings)
	chainsJSON, _ := json.Marshal(req.Chains)
	id := uuid.New().String()

	_, err := r.db.Exec(
		`INSERT INTO hunts (id, target, tech_stack, findings, chains, subdomains, bounty_estimate, summary, hunted_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
		id, req.Target, pq.Array(req.TechStack),
		string(findingsJSON), string(chainsJSON),
		pq.Array(req.Subdomains), req.BountyEstimate, req.Summary,
	)
	if err != nil {
		return model.Hunt{}, fmt.Errorf("save hunt: %w", err)
	}

	return r.GetByID(id)
}

func (r *HuntRepository) GetByID(id string) (model.Hunt, error) {
	row := r.db.QueryRow(
		`SELECT id, target, tech_stack, COALESCE(findings::text, '[]'),
		        COALESCE(chains::text, '[]'), subdomains,
		        bounty_estimate, summary, user_id, hunted_at
		 FROM hunts WHERE id = $1`, id,
	)
	return scanHunt(row)
}

func (r *HuntRepository) Recall(target string) (*model.Hunt, error) {
	row := r.db.QueryRow(
		`SELECT id, target, tech_stack, COALESCE(findings::text, '[]'),
		        COALESCE(chains::text, '[]'), subdomains,
		        bounty_estimate, summary, user_id, hunted_at
		 FROM hunts WHERE target = $1
		 ORDER BY hunted_at DESC LIMIT 1`, target,
	)
	h, err := scanHunt(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func (r *HuntRepository) ListByUser(userID string, limit int) ([]model.Hunt, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := r.db.Query(
		`SELECT id, target, tech_stack, COALESCE(findings::text, '[]'),
		        COALESCE(chains::text, '[]'), subdomains,
		        bounty_estimate, summary, user_id, hunted_at
		 FROM hunts WHERE user_id = $1
		 ORDER BY hunted_at DESC LIMIT $2`, userID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list hunts: %w", err)
	}
	defer rows.Close()

	hunts := []model.Hunt{}
	for rows.Next() {
		h, err := scanHunt(rows)
		if err != nil {
			return nil, err
		}
		hunts = append(hunts, h)
	}
	return hunts, nil
}

func (r *HuntRepository) SearchByTech(techs []string) ([]model.Hunt, error) {
	if len(techs) == 0 {
		return nil, nil
	}

	conditions := []string{}
	args := []interface{}{}
	for i, t := range techs {
		conditions = append(conditions, fmt.Sprintf("$%d = ANY(tech_stack)", i+1))
		args = append(args, t)
	}

	query := fmt.Sprintf(
		`SELECT id, target, tech_stack, COALESCE(findings::text, '[]'),
		        COALESCE(chains::text, '[]'), subdomains,
		        bounty_estimate, summary, user_id, hunted_at
		 FROM hunts WHERE %s
		 ORDER BY hunted_at DESC LIMIT 20`,
		strings.Join(conditions, " OR "),
	)

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("search by tech: %w", err)
	}
	defer rows.Close()

	hunts := []model.Hunt{}
	for rows.Next() {
		h, err := scanHunt(rows)
		if err != nil {
			return nil, err
		}
		hunts = append(hunts, h)
	}
	return hunts, nil
}

func (r *HuntRepository) Delete(id string) error {
	result, err := r.db.Exec("DELETE FROM hunts WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete hunt: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("hunt not found: %s", id)
	}
	return nil
}

func (r *HuntRepository) Stats() (map[string]interface{}, error) {
	stats := map[string]interface{}{}

	var wCount, hCount, uCount int
	var uniqueTargets int
	r.db.QueryRow("SELECT COUNT(*) FROM writeups").Scan(&wCount)
	r.db.QueryRow("SELECT COUNT(*) FROM hunts").Scan(&hCount)
	r.db.QueryRow("SELECT COUNT(DISTINCT target) FROM hunts").Scan(&uniqueTargets)
	r.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&uCount)
	stats["total_writeups"] = wCount
	stats["total_hunts"] = hCount
	stats["unique_targets"] = uniqueTargets
	stats["total_users"] = uCount

	var latestHunt sql.NullTime
	r.db.QueryRow("SELECT MAX(hunted_at) FROM hunts").Scan(&latestHunt)
	if latestHunt.Valid {
		stats["latest_hunt"] = latestHunt.Time.String()
	}

	rows, _ := r.db.Query(
		"SELECT vuln_class, COUNT(*) as c FROM writeups GROUP BY vuln_class ORDER BY c DESC",
	)
	classCounts := map[string]int{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cls string
			var count int
			rows.Scan(&cls, &count)
			classCounts[cls] = count
		}
	}
	stats["writeups_by_class"] = classCounts

	return stats, nil
}
