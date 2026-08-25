package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const defaultEmbedderURL = "http://localhost:9102"

func embedderURL() string {
	if u := os.Getenv("EMBEDDER_URL"); u != "" {
		return u
	}
	return defaultEmbedderURL
}

// EmbedQuery converts a single query string into its embedding vector via
// the embedder microservice, using the same model as ingestion-time
// embedding so query and writeup vectors are comparable.
func EmbedQuery(text string) ([]float32, error) {
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return nil, fmt.Errorf("encode embed request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(embedderURL()+"/embed", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("embedder request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embedder returned status %d", resp.StatusCode)
	}

	var out struct {
		Embeddings [][]float32 `json:"embeddings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode embedder response: %w", err)
	}
	if len(out.Embeddings) == 0 {
		return nil, fmt.Errorf("embedder returned no vectors")
	}

	return out.Embeddings[0], nil
}
