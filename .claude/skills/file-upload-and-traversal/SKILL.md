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

## Video/image-processing pipeline SSRF

Any endpoint that shells out to `ffmpeg` or ImageMagick on an uploaded
file is a candidate SSRF sink -- the file itself, not just its content,
can instruct the processor to fetch an internal URL.

- **FFmpeg HLS playlist SSRF** -- an uploaded `.m3u8` (or a video whose
  processing pipeline touches HLS) can point a segment at an internal
  URL:
  ```
  #EXTM3U
  #EXT-X-MEDIA-SEQUENCE:0
  #EXTINF:10.0,
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  #EXT-X-ENDLIST
  ```
- **FFmpeg concat-demuxer SSRF** -- the same trick via a concat file list
  (`ffconcat version 1.0` + `file 'http://internal-host/path'`) instead
  of a playlist; test both since some pipelines accept only one input
  type.
- **ImageMagick MVG SSRF** -- a crafted `.mvg` (Magick Vector Graphics)
  file, or one renamed to `.jpg`/`.png` to slip past an extension check,
  can trigger an outbound fetch during rendering:
  ```
  push graphic-context
  viewbox 0 0 640 480
  fill 'url(http://169.254.169.254/latest/meta-data/iam/security-credentials/)'
  pop graphic-context
  ```

Confirm via an OOB callback host in the URL, same as any other SSRF --
see the `ssrf` skill's confirmation traps before claiming this as a
finding.
