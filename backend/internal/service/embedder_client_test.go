package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmbedQuery_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/embed" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body.Text != "sql injection in react apps" {
			t.Errorf("unexpected query text: %q", body.Text)
		}
		json.NewEncoder(w).Encode(map[string][][]float32{
			"embeddings": {{0.1, 0.2, 0.3}},
		})
	}))
	defer srv.Close()

	t.Setenv("EMBEDDER_URL", srv.URL)

	vec, err := EmbedQuery("sql injection in react apps")
	if err != nil {
		t.Fatalf("EmbedQuery: %v", err)
	}
	if len(vec) != 3 {
		t.Fatalf("len(vec) = %d, want 3", len(vec))
	}
}

func TestEmbedQuery_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("EMBEDDER_URL", srv.URL)

	if _, err := EmbedQuery("anything"); err == nil {
		t.Fatal("EmbedQuery with a 500 response: want error, got nil")
	}
}

func TestEmbedQuery_EmptyEmbeddings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string][][]float32{"embeddings": {}})
	}))
	defer srv.Close()

	t.Setenv("EMBEDDER_URL", srv.URL)

	if _, err := EmbedQuery("anything"); err == nil {
		t.Fatal("EmbedQuery with an empty embeddings array: want error, got nil")
	}
}
