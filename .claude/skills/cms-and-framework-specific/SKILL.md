---
name: cms-and-framework-specific
description: Per-CMS and per-framework attack checklists -- WordPress/Joomla/Drupal/Magento, backend frameworks (Laravel/Django/Spring Boot/Rails/PHP), and a long tail of other CMS/dev-tool products (Confluence, GitLab, Jenkins, Jira, SharePoint, phpMyAdmin, MediaWiki, Kibana, Grafana, Fuel CMS, Bolt CMS, Roundcube) with their known CVE classes. Converted from master-pentest-prompt.md Phases 27/31. Use as soon as fingerprinting identifies any of these products, before generic technique testing.
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
  recurring class worth checking every engagement).
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
  debug mode leaking `.env` contents.
- **Django**: `DEBUG=True` stack traces that leak `SECRET_KEY`;
  `PickleField` RCE; SQLi via the ORM's `.extra()`/`.annotate()` escape
  hatches; CSRF via JSON bodies (Django's CSRF token often isn't checked
  on JSON content-type requests).
- **Spring/Spring Boot**: `/actuator/env`, `/heapdump` secrets,
  `/jolokia`, SpEL RCE via user-controlled properties, the
  CVE-2022-22965 (Spring4Shell) RCE class.
- **Rails**: mass assignment via `attr_accessible` misconfiguration,
  `secret_key_base` leakage, unsafe params deserialization, and a
  Brakeman-style scan across all routes as a baseline.
- **General PHP frameworks**: `composer.lock`-derived CVEs, debug
  endpoints left enabled, `unserialize()` sinks in legacy code, and
  `phpinfo()` output leaking environment variables.

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
  CVEs, GraphQL user enumeration.
- **Jenkins**: script-console RCE, Groovy sandbox escapes, unauthenticated
  project-config access, CVE-2024-23897 (args4j arbitrary file read).
- **Jira**: `/secure/QuickEdit.jspa` IDOR, CVE-2017-9506,
  CVE-2019-11581.
- **SharePoint**: unauthenticated SSRF (CVE-2021-34473), ViewState RCE.
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
