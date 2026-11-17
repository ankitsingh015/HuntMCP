import os
import chromadb
from chromadb import PersistentClient

CHROMA_DIR = os.getenv("CHROMA_DIR", os.path.join(os.path.dirname(__file__), "../../data/chroma"))
COLLECTION_NAME = "writeups"

_client = None
_collection = None


def get_client() -> PersistentClient:
    global _client
    if _client is None:
        os.makedirs(CHROMA_DIR, exist_ok=True)
        _client = chromadb.PersistentClient(path=CHROMA_DIR)
    return _client


def get_collection():
    global _collection
    if _collection is None:
        client = get_client()
        existing = [c.name for c in client.list_collections()]
        if COLLECTION_NAME in existing:
            _collection = client.get_collection(COLLECTION_NAME)
        else:
            _collection = client.create_collection(
                COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
    return _collection


def query(query_embeddings: list[list[float]], top_k: int = 5):
    collection = get_collection()
    results = collection.query(
        query_embeddings=query_embeddings,
        n_results=top_k,
        include=["metadatas", "distances", "documents"],
    )
    return results


def upsert_chunks(
    ids: list[str],
    embeddings: list[list[float]],
    documents: list[str],
    metadatas: list[dict],
):
    collection = get_collection()
    collection.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=documents,
        metadatas=metadatas,
    )


def delete_by_url(url: str) -> int:
    """Delete every chunk whose metadata url matches (all chunks of one report).
    Returns the count removed. Used to supersede an older copy of a report (e.g.
    an h1_fetch version) before embedding a cleaner HexBrain version -- both
    share the same hackerone.com/reports/<id> url, so this clears any source."""
    if not url:
        return 0
    collection = get_collection()
    existing = collection.get(where={"url": url})
    ids = (existing or {}).get("ids", []) or []
    if ids:
        collection.delete(ids=ids)
    return len(ids)


def collection_stats() -> dict:
    collection = get_collection()
    return {"count": collection.count(), "name": COLLECTION_NAME}
