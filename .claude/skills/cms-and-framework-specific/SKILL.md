---
name: cms-and-framework-specific
description: Per-CMS and per-framework attack checklists -- WordPress/Joomla/Drupal/Magento, backend frameworks (Laravel/Django/Spring Boot/Rails/PHP/FastAPI/NestJS/Next.js/Node.js/ASP.NET), and a long tail of other CMS/dev-tool products (Confluence, GitLab, Jenkins, Jira, SharePoint, phpMyAdmin, MediaWiki, Kibana, Grafana, Fuel CMS, Bolt CMS, Roundcube, Zimbra, Exchange/OWA) with their known CVE classes. Converted from master-pentest-prompt.md Phases 27/31. Use as soon as fingerprinting identifies any of these products, before generic technique testing.
---

# CMS & framework-specific

## When to use

As soon as recon/fingerprinting identifies one of these products
specifically -- product-specific known vulnerability classes are almost
always higher-yield than generic technique testing once the exact
product and version are known.

## Mainstream CMS

- **WordPress**: `wp-login` brute force (including the classic
  `xmlrpc.php` `system.multicall` amplification bypass for rate limits),
  `wp-json/wp/v2/users` enumeration, plugin/theme CVEs (check
  exploit-db/WPScan against the fingerprinted versions), `wp-config.php`
  exposure, author enumeration via `?author=1`, upload bypass to `.php`/
  `.phtml`, XML-RPC pingback SSRF, unauthenticated-RCE plugins (a
  recurring class worth checking every engagement). Concrete plugin-CVE
  table worth checking by exact version (cross-check `readme.txt`
  `Stable tag`, the plugin-header `Version:`, and asset `?ver=` query
  strings -- `readme.txt` alone often lags a real patch): Slider
  Revolution < 6.6.20 -> CVE-2024-2534 RCE (< 6.5.8 -> CVE-2022-2944
  SQLi); Gravity Forms < 2.8.2 -> CVE-2024-6115 PHP object injection;
  ElementsKit < 2.9.4 -> CVE-2023-6851 SQLi / CVE-2023-6853 file upload;
  WPDM (Download Manager) < 3.3.00 -> CVE-2023-49753 SQLi. Observed
  frequency across a 58-site mass-recon pass: 7/58 had vulnerable
  ElementsKit, 5/58 had Revslider installed, and 5/7 deep-dive targets
  also had CORS credential reflection on `/wp-json/wp/v2/users` --
  plugin CVEs and WP REST misconfig routinely co-occur on the same
  target.
- **Joomla**: configuration-permutation brute force, admin login via the
  `user` parameter, file-download/view CVEs, unauthenticated SQLi
  classes.
- **Drupal**: classic user-login SQLi CVEs, REST module access-control
  bypass, the Drupalgeddon family, JSON:API field-access issues.
- **Magento**: `/admin` panel bypass, SSRF in the image endpoint, RCE via
  admin templates -- an unsupported/EOL Magento version alone implies a
  large known-CVE surface.

## Backend frameworks

- **Laravel**: `APP_KEY` leak -> decrypt the session cookie -> RCE via
  deserialization; `/_ignition` execute-solution RCE (CVE-2021-3129);
  debug mode leaking `.env` contents. Telescope (`/telescope/api/*`) and
  Horizon (`/horizon/api/*`) dashboards left exposed leak DB queries,
  Redis commands, and failed-job payloads wholesale -- failed-job
  payloads especially often carry full request data including auth
  tokens; signed-URL manipulation -- `URL::signedRoute` sometimes
  validates only some parameters, so swapping a non-signature field
  (e.g. `user=123` -> `user=999`) or appending an unvalidated extra
  param can bypass intent while the signature stays valid; queue-worker
  abuse via mass-assigned job payloads reaching Horizon's failed-job
  replay.
- **Django**: `DEBUG=True` stack traces that leak `SECRET_KEY`;
  `PickleField` RCE; SQLi via the ORM's `.extra()`/`.annotate()` escape
  hatches; CSRF via JSON bodies (Django's CSRF token often isn't checked
  on JSON content-type requests). DRF (Django REST Framework) permission
  gaps: list/retrieve/custom `@action` endpoints on the same viewset can
  carry different (or missing) permission classes -- `@action`-decorated
  methods in particular are a recurring spot where the class-level
  `permission_classes` doesn't get inherited. Django admin-panel
  exploitation: enumerate the panel at `/admin/`, `/django-admin/`, or a
  custom path, then brute-force cautiously (heavily logged) since a weak
  admin credential is full-app compromise, not just data access.
- **Spring/Spring Boot**: `/actuator/env`, `/heapdump` secrets,
  `/jolokia`, SpEL RCE via user-controlled properties, the
  CVE-2022-22965 (Spring4Shell) RCE class. Jolokia mechanics: `/jolokia`
  or `/actuator/jolokia` exposes JMX MBeans over HTTP --
  `/jolokia/list` enumerates operations, `/jolokia/read/java.lang:type=
  Runtime/SystemProperties` can leak credentials baked into system
  properties, and `/jolokia/exec/...` against an MLet-capable MBean
  reaches RCE. H2 console mechanics: `/h2-console` (default creds
  `sa`/empty) allows arbitrary SQL, and `CREATE ALIAS EXEC AS $$ String
  exec(String cmd) throws Exception { return new String(Runtime
  .getRuntime().exec(new String[]{"sh","-c",cmd})
  .getInputStream().readAllBytes()); } $$;` followed by `CALL
  EXEC('id')` turns that into OS command execution.
- **Rails**: mass assignment via `attr_accessible` misconfiguration,
  `secret_key_base` leakage, unsafe params deserialization, and a
  Brakeman-style scan across all routes as a baseline.
- **General PHP frameworks**: `composer.lock`-derived CVEs, debug
  endpoints left enabled, `unserialize()` sinks in legacy code, and
  `phpinfo()` output leaking environment variables.
- **FastAPI**: dependency-injection auth gaps -- `Depends`-guarded
  routes that fall through when a route overrides a sub-dependency to
  `None`, or when work scheduled via `BackgroundTasks` skips the auth
  dependency entirely; Pydantic type-coercion bypass (a string `"true"`
  silently coerced to a boolean, or Pydantic v1's default of ignoring
  extra fields letting an unexpected `role`/`is_admin` field ride along
  to a DB write); OpenAPI schema mining -- pull `/openapi.json` (or
  `/docs`/`/redoc` if that 403s) and grep `.paths` for GET operations
  with `security: []` that aren't surfaced in the public docs UI.
- **NestJS**: guard bypass via the decorator stack -- `@UseGuards()`
  resolves global -> controller -> method, and a Reflector
  metadata-key mismatch between layers can leave the global guard with
  no metadata to check, so it passes by default; `ValidationPipe`'s
  `whitelist`+`transform` combination coerces primitive strings to
  booleans/numbers before validation runs, and `skipMissingProperties`
  on a PATCH lets an attacker submit only the field they want changed
  (e.g. `{"role":"admin"}`) with no other-field validation triggered;
  a missing `ClassSerializerInterceptor` leaks full entity fields
  (password hashes, internal notes) that `@Exclude()` should have
  stripped.
- **Next.js**: Server Actions often enforce auth client-side only --
  calling the action directly via the `Next-Action` header bypasses
  UI-layer checks entirely; ISR (Incremental Static Regeneration) cache
  poisoning by injecting a unique marker through a query/URL param that
  influences the cached page, then confirming via `x-nextjs-cache`/`age`
  headers on a *separate*, clean-URL fetch (a reflected marker alone is
  not proof of poisoning -- it has to persist in the cache and be served
  to a different client); `/_next/image?url=` SSRF via the
  image-optimization endpoint, only confirmable via an OOB callback to a
  unique Collaborator subdomain -- a 200 returns an optimized *image*,
  not the upstream response body, so status code alone never proves
  SSRF, and a 400 on a non-whitelisted URL is `images.remotePatterns`
  working as intended, not a bypassed filter.
- **Node.js/Express**: prototype-pollution-to-RCE chains specific to
  Express middleware -- `__proto__`/`constructor.prototype` injection
  via `body-parser`/`qs` reaching a `child_process` sink (a polluted
  `shell`/`NODE_OPTIONS` property) or an EJS/Pug render call
  (CVE-2022-29078-style `outputFunctionName` pollution); `trust proxy`
  misconfiguration (`app.set('trust proxy', true)`) letting a spoofed
  `X-Forwarded-For` bypass IP allowlists and login rate limits. See
  injection-and-rce for the general prototype-pollution gadget-chain
  primer -- this is the Express-specific middleware/sink mechanics on
  top of it, not a restatement of it.
- **ASP.NET (Webforms/WCF)**: ViewState dual-parser MAC-bypass -- send
  several ViewState shapes (trivial garbage, real, flipped-bit, oversize,
  XML-shaped, LosFormatter-prefixed) and diff the error strings;
  `"Validation of viewstate MAC failed"` vs `"The state information is
  invalid for this page and might be corrupted"` proves two distinct
  deserialization entry points exist, one of which (legacy
  `ObjectStateFormatter`) dispatches before the MAC check on certain
  payload shapes. machineKey recovery/derivation: `__VIEWSTATEENCRYPTED
  =""` means ViewState is signed-only, not encrypted, so recovering just
  the `validationKey` (web.config disclosure, `elmah.axd`, a source
  leak) is enough to forge ViewState with `ysoserial.net` -- no
  decryption key needed. `trace.axd`/`elmah.axd` left enabled leak full
  request/response dumps and stack traces (including live
  `Authorization` headers and connection strings) to anonymous users.

For all of the above: enumerate known CVEs for the exact fingerprinted
version (writeup-mcp's `fetch_cves`, or `nuclei-mcp`'s CVE templates),
and check for unsupported/EOL versions first -- those are disclosure-free
wins once confirmed.

## Other CMS / dev-tool products (the long tail)

- **Fuel CMS**: eval-based RCE, CVE-2018-16763 (`cmd` parameter in
  `fuel/pages/select/?filter`).
- **Bolt CMS**: authenticated RCE via Twig theme-template injection.
- **Roundcube**: stored XSS, skin-based bypasses, the CVE-2021-49113
  class.
- **Confluence**: OGNL RCE (CVE-2021-26084, CVE-2022-26134), and
  CVE-2023-22515.
- **GitLab**: unauthenticated SSRF (CVE-2021-22214), CE/EE file-read
  CVEs, GraphQL user enumeration. Separately, a different angle worth
  running on any public/registration-open instance: unauthenticated
  API recon -- `/api/v4/projects?visibility=public` enumerates every
  public repo, `/api/v4/projects/:id/repository/files/:path/raw?ref=
  main` dumps raw file contents with no auth needed (check by name for
  `.env`, `.gitlab-ci.yml`, `docker-compose.yml`, `credentials.json`/
  `service-account.json`, `config/database.yml`/`secrets.yml`), and
  `.gitlab-ci.yml` contents routinely reveal CI variable names and
  runner-registration tokens even when `/api/v4/projects/:id/variables`
  itself is admin-gated.
- **Jenkins**: script-console RCE, Groovy sandbox escapes, unauthenticated
  project-config access, CVE-2024-23897 (args4j arbitrary file read).
- **Jira**: `/secure/QuickEdit.jspa` IDOR, CVE-2017-9506,
  CVE-2019-11581.
- **SharePoint**: unauthenticated SSRF (CVE-2021-34473), ViewState RCE;
  the CVE-2025-53770/53771 "ToolShell" chain -- anonymous `GET
  /_layouts/15/ToolPane.aspx?DisplayMode=Edit` (reachable via the
  CVE-2025-49706 auth bypass, a crafted `Referer` header) returning
  `__VIEWSTATEENCRYPTED=""` (signed-only ViewState), combined with an
  anonymous `POST /_api/contextinfo` minting a valid `FormDigestValue`,
  lets an anonymous `POST` back to ToolPane with that digest reach the
  CVE-2025-49704 deserialization sink for RCE with no machineKey needed
  up front -- the machineKey is then dumped by the resulting webshell
  for persistence. Permanent zero-day on EoL SharePoint 2013 (support
  ended 2023-04-11, so it never gets patched); confirming the three-step
  precondition chain (anon GET -> anon FormDigest POST -> anon
  digest-bearing POST) without delivering an actual payload is
  sufficient evidence for a report.
- **Zimbra**: unauthenticated SOAP user enumeration via
  `/service/soap/` `AuthRequest` -- `"authentication failed"`
  differentiates a valid username (wrong password) from `"no such
  account"` (invalid); CVE-2022-37042 UploadServlet path traversal
  (`/service/upload?fmt=extended`, pre-9.0.0-P27/8.8.15-P34) allows
  unauthenticated file write; admin console access at `/zimbraAdmin/`
  (or directly on port 7071 if port-forwarded) and `/service/proxy?
  target=` internal SSRF toward cloud metadata/internal services
  (unauthenticated pre-8.8.15, low-priv-authenticated after).
- **Exchange/OWA**: pre-auth NTLM Type-2 challenge decode -- send a
  Type-1 Negotiate to `/owa/` and parse the `WWW-Authenticate: NTLM`/
  `Negotiate` Type-2 response's AV_PAIRS for NetBIOS domain, DNS
  domain/forest, and computer name, all leaked with zero authentication
  and zero shell; `X-OWA-Version` maps directly to product/CU
  (`15.1.x` = Exchange 2016, `15.2.x` = Exchange 2019) for CVE matching;
  password-spray considerations -- confirm lockout policy with one
  known-bad password before spraying, since `/owa/auth.owa` response
  timing/code uniformity across attempts reveals whether rate limiting
  exists at all.
- **phpMyAdmin**: CVE-2016-5734 RCE, `LOAD DATA LOCAL` abuse, exposed
  setup wizard.
- **MediaWiki**: CVE-2019-20203 eval-based issue, general API abuse.
- **Kibana/Elasticsearch**: CVE-2019-7609 prototype-pollution RCE,
  unauthenticated `_search?q=` giving arbitrary query access, script
  fields used for RCE.
- **Grafana**: `/public/plugins/` directory traversal for file read.
- **Others worth a quick CVE check when fingerprinted**: Ghost,
  PrestaShop, Concrete5, ExpressionEngine, and any WordPress plugin
  ecosystem product; Drupal 8's own CVE-2018-7600 (Drupalgeddon2) is
  distinct enough from the Drupal bullet above to check separately by
  version.
