"""Embedding microservice for HuntMCP.

Converts writeup text to 384-dim vectors using sentence-transformers.
Runs only during ingestion/reindexing — never in the live API path.
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

from sentence_transformers import SentenceTransformer

MODEL_NAME = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
model = SentenceTransformer(MODEL_NAME)


class EmbeddingHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/embed":
            self.send_error(404, "Not found. Use POST /embed")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body)
            texts = data.get("texts", data.get("text", []))
            if isinstance(texts, str):
                texts = [texts]
        except (json.JSONDecodeError, TypeError) as e:
            self.send_error(400, f"Invalid JSON: {e}")
            return

        if not texts:
            self.send_error(400, "Missing 'texts' or 'text' field")
            return

        embeddings = model.encode(texts, normalize_embeddings=True).tolist()

        response = json.dumps({"embeddings": embeddings}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        if self.path == "/health":
            response = json.dumps({
                "status": "ok",
                "model": MODEL_NAME,
                "dimension": model.get_sentence_embedding_dimension(),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_error(404)


def main():
    port = int(os.getenv("EMBEDDER_PORT", "9102"))
    server = HTTPServer(("0.0.0.0", port), EmbeddingHandler)
    print(f"Embedder started on :{port} with model {MODEL_NAME}")
    print(f"  Embedding dimension: {model.get_sentence_embedding_dimension()}")
    server.serve_forever()


if __name__ == "__main__":
    main()
