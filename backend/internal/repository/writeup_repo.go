package repository

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ankitsingh015/HuntMCP/backend/internal/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

type WriteupRepository struct {
	db *DB
}

func NewWriteupRepository(db *DB) *WriteupRepository {
	return &WriteupRepository{db: db}
}

type WriteupRow struct {
	ID         string
	Title      string
	URL        sql.NullString
	VulnClass  string
	TargetTech []string
	Bounty     sql.NullInt64
	Author     sql.NullString
	Content    string
	SourceType string
	CreatedAt  time.Time
}

func scanWriteup(scanner interface {
	Scan(dest ...interface{}) error
}) (model.Writeup, error) {
	var row WriteupRow
	err := scanner.Scan(
		&row.ID, &row.Title, &row.URL, &row.VulnClass,
		pq.Array(&row.TargetTech), &row.Bounty, &row.Author,
		&row.Content, &row.SourceType, &row.CreatedAt,
	)
	if err != nil {
		return model.Writeup{}, err
	}
	w := model.Writeup{
		ID:         row.ID,
		Title:      row.Title,
		VulnClass:  row.VulnClass,
		TargetTech: row.TargetTech,
		Content:    row.Content,
		SourceType: row.SourceType,
		CreatedAt:  row.CreatedAt,
	}
	if row.URL.Valid {
		w.URL = row.URL.String
	}
	if row.Bounty.Valid {
		w.Bounty = int(row.Bounty.Int64)
	}
	if row.Author.Valid {
		w.Author = row.Author.String
	}
	return w, nil
}

func (r *WriteupRepository) Create(req model.WriteupCreateRequest) (model.Writeup, error) {
	id := uuid.New().String()
	_, err := r.db.Exec(
		`INSERT INTO writeups (id, title, url, vuln_class, target_tech, bounty, author, content, source_type)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, req.Title, req.URL, req.VulnClass,
		pq.Array(req.TargetTech), req.Bounty, req.Author,
		req.Content, "api",
	)
	if err != nil {
		return model.Writeup{}, fmt.Errorf("create writeup: %w", err)
	}
	return r.GetByID(id)
}

func (r *WriteupRepository) GetByID(id string) (model.Writeup, error) {
	row := r.db.QueryRow(
		`SELECT id, title, COALESCE(url,''), vuln_class, target_tech,
		        COALESCE(bounty,0), COALESCE(author,''), content, source_type, created_at
		 FROM writeups WHERE id = $1`, id,
	)
	return scanWriteup(row)
}

func (r *WriteupRepository) List(page, perPage int, vulnClass, tech, search string) (model.WriteupListResponse, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	if vulnClass != "" {
		conditions = append(conditions, fmt.Sprintf("vuln_class = $%d", argIdx))
		args = append(args, vulnClass)
		argIdx++
	}
	if tech != "" {
		conditions = append(conditions, fmt.Sprintf("$%d = ANY(target_tech)", argIdx))
		args = append(args, tech)
		argIdx++
	}
	if search != "" {
		conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR content ILIKE $%d)", argIdx, argIdx+1))
		args = append(args, "%"+search+"%", "%"+search+"%")
		argIdx += 2
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM writeups %s", whereClause)
	if err := r.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return model.WriteupListResponse{}, fmt.Errorf("count writeups: %w", err)
	}

	offset := (page - 1) * perPage
	query := fmt.Sprintf(
		`SELECT id, title, COALESCE(url,''), vuln_class, target_tech,
		        COALESCE(bounty,0), COALESCE(author,''), content, source_type, created_at
		 FROM writeups %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		whereClause, argIdx, argIdx+1,
	)
	args = append(args, perPage, offset)

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return model.WriteupListResponse{}, fmt.Errorf("list writeups: %w", err)
	}
	defer rows.Close()

	writeups := []model.Writeup{}
	for rows.Next() {
		w, err := scanWriteup(rows)
		if err != nil {
			return model.WriteupListResponse{}, err
		}
		writeups = append(writeups, w)
	}

	return model.WriteupListResponse{
		Writeups: writeups,
		Total:    total,
		Page:     page,
		PerPage:  perPage,
	}, nil
}

func (r *WriteupRepository) Update(id string, req model.WriteupUpdateRequest) (model.Writeup, error) {
	fields := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.Title != nil {
		fields = append(fields, fmt.Sprintf("title = $%d", argIdx))
		args = append(args, *req.Title)
		argIdx++
	}
	if req.VulnClass != nil {
		fields = append(fields, fmt.Sprintf("vuln_class = $%d", argIdx))
		args = append(args, *req.VulnClass)
		argIdx++
	}
	if req.Content != nil {
		fields = append(fields, fmt.Sprintf("content = $%d", argIdx))
		args = append(args, *req.Content)
		argIdx++
	}
	if req.TargetTech != nil {
		fields = append(fields, fmt.Sprintf("target_tech = $%d", argIdx))
		args = append(args, pq.Array(req.TargetTech))
		argIdx++
	}
	if req.Bounty != nil {
		fields = append(fields, fmt.Sprintf("bounty = $%d", argIdx))
		args = append(args, *req.Bounty)
		argIdx++
	}
	if req.Author != nil {
		fields = append(fields, fmt.Sprintf("author = $%d", argIdx))
		args = append(args, *req.Author)
		argIdx++
	}
	if req.URL != nil {
		fields = append(fields, fmt.Sprintf("url = $%d", argIdx))
		args = append(args, *req.URL)
		argIdx++
	}

	if len(fields) == 0 {
		return r.GetByID(id)
	}

	args = append(args, id)
	query := fmt.Sprintf(
		"UPDATE writeups SET %s WHERE id = $%d",
		strings.Join(fields, ", "), argIdx,
	)
	if _, err := r.db.Exec(query, args...); err != nil {
		return model.Writeup{}, fmt.Errorf("update writeup: %w", err)
	}
	return r.GetByID(id)
}

func (r *WriteupRepository) Delete(id string) error {
	result, err := r.db.Exec("DELETE FROM writeups WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete writeup: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("writeup not found: %s", id)
	}
	return nil
}

func (r *WriteupRepository) VectorSearch(query []float32, topK int, minScore float64) ([]model.RAGQueryResult, error) {
	if topK < 1 || topK > 50 {
		topK = 10
	}
	if minScore <= 0 {
		minScore = 0.5
	}

	rows, err := r.db.Query(
		`SELECT id, title, COALESCE(url,''), vuln_class, target_tech,
		        COALESCE(bounty,0), COALESCE(author,''), content, source_type, created_at,
		        1 - (embedding <=> $1::vector) AS similarity
		 FROM writeups
		 WHERE embedding IS NOT NULL
		   AND 1 - (embedding <=> $1::vector) > $2
		 ORDER BY similarity DESC
		 LIMIT $3`,
		pq.Array(query), minScore, topK,
	)
	if err != nil {
		return nil, fmt.Errorf("vector search: %w", err)
	}
	defer rows.Close()

	results := []model.RAGQueryResult{}
	for rows.Next() {
		var row WriteupRow
		var similarity float64
		err := rows.Scan(
			&row.ID, &row.Title, &row.URL, &row.VulnClass,
			pq.Array(&row.TargetTech), &row.Bounty, &row.Author,
			&row.Content, &row.SourceType, &row.CreatedAt,
			&similarity,
		)
		if err != nil {
			return nil, err
		}
		w := model.Writeup{
			ID:         row.ID,
			Title:      row.Title,
			VulnClass:  row.VulnClass,
			TargetTech: row.TargetTech,
			Content:    row.Content,
			SourceType: row.SourceType,
			CreatedAt:  row.CreatedAt,
		}
		if row.URL.Valid {
			w.URL = row.URL.String
		}
		if row.Bounty.Valid {
			w.Bounty = int(row.Bounty.Int64)
		}
		if row.Author.Valid {
			w.Author = row.Author.String
		}
		results = append(results, model.RAGQueryResult{
			Writeup:    w,
			Similarity: similarity,
		})
	}

	return results, nil
}

func (r *WriteupRepository) BatchCreate(writeups []model.WriteupCreateRequest) (int, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	count := 0
	for _, w := range writeups {
		id := uuid.New().String()
		_, err := tx.Exec(
			`INSERT INTO writeups (id, title, url, vuln_class, target_tech, bounty, author, content, source_type)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			id, w.Title, w.URL, w.VulnClass,
			pq.Array(w.TargetTech), w.Bounty, w.Author,
			w.Content, "batch",
		)
		if err != nil {
			return 0, fmt.Errorf("batch insert: %w", err)
		}
		count++
	}

	return count, tx.Commit()
}

func (r *WriteupRepository) ReindexAll(embeddings map[string][]float32) error {
	for id, vec := range embeddings {
		_, err := r.db.Exec(
			"UPDATE writeups SET embedding = $1::vector WHERE id = $2",
			pq.Array(vec), id,
		)
		if err != nil {
			return fmt.Errorf("reindex writeup %s: %w", id, err)
		}
	}
	return nil
}

func (r *WriteupRepository) GetUnembedded() ([]model.Writeup, error) {
	rows, err := r.db.Query(
		`SELECT id, title, COALESCE(url,''), vuln_class, target_tech,
		        COALESCE(bounty,0), COALESCE(author,''), content, source_type, created_at
		 FROM writeups WHERE embedding IS NULL`,
	)
	if err != nil {
		return nil, fmt.Errorf("get unembedded: %w", err)
	}
	defer rows.Close()

	writeups := []model.Writeup{}
	for rows.Next() {
		w, err := scanWriteup(rows)
		if err != nil {
			return nil, err
		}
		writeups = append(writeups, w)
	}
	return writeups, nil
}
