import hashlib
import re
import yaml
from typing import Any


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)", text, re.DOTALL)
    if match:
        frontmatter = yaml.safe_load(match.group(1)) or {}
        body = match.group(2).strip()
    else:
        frontmatter = {}
        body = text.strip()
    return frontmatter, body


def chunk_text(text: str, chunk_size: int = 1024, overlap: int = 128) -> list[str]:
    if not text:
        return []
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunk = text[start:end]
        chunks.append(chunk)
        start += chunk_size - overlap
    return chunks


def chunk_writeup(
    filepath: str,
    chunk_size: int = 1024,
    overlap: int = 128,
) -> list[dict[str, Any]]:
    with open(filepath) as f:
        content = f.read()
    frontmatter, body = parse_frontmatter(content)
    text_chunks = chunk_text(body, chunk_size, overlap)
    base_meta = {
        "title": frontmatter.get("title", "Untitled"),
        "url": frontmatter.get("url", ""),
        "vuln_class": frontmatter.get("vuln_class", "unknown"),
        "tech": frontmatter.get("tech", "unknown"),
        "bounty": str(frontmatter.get("bounty", "0")),
        "source": filepath,
    }
    # IDs keyed on title alone collide silently in ChromaDB (overwriting one
    # writeup's chunks with another's) whenever two writeups share a title or
    # both fall back to "Untitled". Mix in a hash of the source path so ids
    # stay unique per file regardless of title.
    file_id = hashlib.sha1(filepath.encode()).hexdigest()[:12]
    result = []
    for i, text in enumerate(text_chunks):
        result.append({
            "text": text,
            "metadata": {**base_meta, "chunk_index": str(i)},
            "id": f"{file_id}-chunk{i}",
        })
    return result
