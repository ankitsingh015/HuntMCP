---
name: injection-and-rce
description: Full injection-class technique list (SQLi, command injection, LDAP/XPath/XSLT/EL, SSTI, CRLF, HPP, prototype pollution) and remote-code-execution technique list (deserialization, file-upload webshells, LFI/RFI, framework-specific RCE, dependency CVEs). Converted from master-pentest-prompt.md Phases 2/3. Use during scan-agent's injection-testing pass on any target with user-controlled input reaching a backend.
---

# Injection and RCE

## When to use

scan-agent's injection-testing pass on any parameter, header, or body
field that reaches a backend. RCE techniques are often the escalation
path once an injection point is confirmed -- test injection first, then
check whether it chains into RCE via this skill's second half.

## All injections (injection overload)

- **SQLi**: UNION / blind / time / error / second-order / NoSQLi / ORM
  (HQL, GraphQL) -- `sqlmap-mcp` covers the automatable cases; see
  `knowledge/payloads/sqli.txt` for curated payloads when it misses
  something.
- **Command injection**: blind, out-of-band (DNS/HTTP callback via
  `oob-mcp`).
- **OS command chaining**: `;`, `|`, `&&`, `$()`, newlines, encoded
  bypasses.
- **Shellshock vectors** in User-Agent, Referer, Cookie.
- **LDAP, XPath, XQuery, XSLT, EL** (SpEL/OGNL), **SSTI**
  (Jinja2/Twig/Freemarker) -- see `knowledge/payloads/ssti.txt`.
- **CRLF -> Header Injection -> Cache Poisoning -> Stored XSS** chain.
- **HTTP Parameter Pollution (HPP)**: `;` vs `&`, duplicate params, JSON
  vs form encoding.
- **Hidden parameter tampering** (Param Miner style): `debug`, `test`,
  `source`, `deprecated`.
- **Server-side prototype pollution -> RCE** -- see
  `knowledge/payloads/prototype-pollution.txt`.
- **Domain/polyglot payloads** (SSTImap, smapcap style).

## RCE & code execution -- don't skip any

- **Deserialization**: PHP POP chains, Java (ysoserial:
  CommonsCollections, Spring, JDK), .NET (ViewState, ysoserial.net),
  Python (pickle/PyYAML), Ruby Marshal, Node.js (`node-serialize`), .NET
  `BinaryFormatter`.
- **File upload -> webshell** (double extension, null byte, magic byte,
  polyglot, `.htaccess`, SVG/XML, image with embedded PHP) -- see the
  `file-upload-and-traversal` skill for the full upload-bypass matrix.
- **LFI/RFI** -> `/proc/self/environ`, `php://input`, log poisoning,
  `data://`, `expect://`, other wrappers.
- **SSRF -> RCE** via internal Redis/Memcached/Hadoop/Elasticsearch/Minio
  -- see the `ssrf` skill.
- **XXE** -> `expect://`, PHP wrappers, FTP OOB.
- **ImageMagick** (ImageTragick, CVE-2016-3714), **LaTeX injection**.
- **Zip Slip / Tar Slip / symlink traversal** -- RCE on unpack.
- **Framework-specific**: Struts2 (OGNL), Spring4Shell, Log4Shell, Shiro,
  Laravel `APP_KEY`, Django `SECRET_KEY`, Rails mass-assignment.
- **Dependency CVEs**: grep every lockfile against a CVE DB
  (writeup-mcp's `fetch_cves`).
- **gRPC/Thrift/RMI/Java RMI** attack surface.
- **Unsafe `eval()`/`Function()`/`exec()` reflection** in server-side
  JS/PHP.
- **Serverless function injection** (temp files, env vars).
- **Cron/queue/worker deserialization RCE**.
- **Prototype pollution -> SSRF -> RCE** chains.
- **Client-side**: DOM clobbering for client RCE, Electron
  `contextIsolation` bypass.
- **First-class escalation path**: desync/request smuggling (see the
  `request-smuggling` skill) chained into RCE.

## Real disclosed reports (precedent, not just theory)

These confirm the technique classes above paid out on real programs, not
just in theory:

- **SQLi**: HackerOne #2599826 (U.S. DoD, blind boolean-based SQLi via
  the `User-Agent` header -- a header-based injection point, not just a
  query param), #1069561 (Automattic, SQLi in intensedebate.com),
  #962889 (Acronis, SQLi in `agent-manager`).
- **RCE via deserialization**: HackerOne #1174185 (U.S. DoD, RCE via
  insecure deserialization in Telerik UI, CVE-2019-18935), #274990
  (RubyGems, RCE via deserialization on rubygems.org itself -- a
  reminder that package-registry infrastructure is as much a target as
  the applications built on it), #1248052 (U.S. DoD, pre-auth RCE in
  ForgeRock OpenAM via unsafe Java deserialization in its Jato
  framework, CVE-2021-35464).

The DoD reports are a useful pattern on their own: government bug bounty
programs disclose at high volume and tend toward exactly the boring,
systematic injection classes in this skill (header-based SQLi, known-CVE
deserialization in a bundled third-party component) rather than exotic
chains -- confirming that thorough coverage of the basics here is
higher-yield than hunting for novelty.
