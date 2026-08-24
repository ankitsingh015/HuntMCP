---
name: file-upload-and-traversal
description: Path traversal encodings, the file-upload bypass matrix (extension/MIME/magic-byte checks), and file-format-specific attacks (SVG/DOCX/XLSX XXE, PDF launch actions, polyglot images). Converted from master-pentest-prompt.md Phase 6. Use on any file-upload feature or any endpoint that takes a file path/name as input.
---

# File upload & traversal

## When to use

Any upload feature (avatar, document, import), and any endpoint that
builds a file path from user input (download-by-filename, template
selection, log viewers).

## Path traversal

All encodings: `..%2f`, `%252e%252e`, `//`, dot-bypass variants. File
*write* via traversal (overwrite a config file to get RCE) is a strictly
higher-impact variant of file *read* -- always check whether an upload or
export feature that accepts a path/filename can be steered to write
outside the intended directory, not just read outside it.

## Upload bypass matrix

- Extension whitelist bypass, MIME-type sniff bypass, magic-byte bypass.
- Double extension (`shell.php.jpg`), null byte, Unicode tricks, case
  swap (`shell.PHP`).
- `.phtml`/`.php5`/`.phar` and other executable-adjacent extensions the
  whitelist might miss.

## File-format-specific attacks

- SVG + XXE, DOCX/XLSX XXE (Office Open XML formats embed XML
  internally).
- PDF JS/launch actions.
- ImageTragick, polyglot JPEG/PNG/WebP with an embedded PHP payload.
- EXIF data with a payload, ZIP archive symlink tricks.
