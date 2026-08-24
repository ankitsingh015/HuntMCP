---
name: methodology-framework-mapping
description: How to map every finding to industry-standard frameworks for the final report -- MITRE ATT&CK tactic/technique IDs, PTES phase alignment, OWASP WSTG test-case numbering, CVSS 3.1 vector scoring, CWE IDs, and CISA KEV catalog cross-referencing. Converted from master-pentest-prompt.md Phase 36. Use while writing up each finding, not during active testing.
---

# Methodology frameworks -- map the report to industry standards

## When to use

While writing up each finding for the report, not during active
testing -- this is a scoring/classification pass applied after a
vulnerability is already confirmed.

## MITRE ATT&CK

Map each finding to its ATT&CK tactic and technique ID (e.g. Initial
Access TA0001 for an unauthenticated RCE, chaining forward through
whatever privilege-escalation tactic the finding enables). This gives
the report a standard vocabulary that security teams already use
internally.

## PTES phase alignment

Frame the report's narrative in PTES's own phase order -- pre-engagement
interactions, intelligence gathering, threat modeling, vulnerability
analysis, exploitation, post-exploitation, reporting -- which
conveniently doubles as a reasonable execution order for the engagement
itself, not just a reporting structure.

## OWASP WSTG numbering

Tag each test performed with its WSTG identifier: `WSTG-INFO`
(information gathering), `WSTG-CONF` (configuration), `WSTG-IDNT`
(identity management), `WSTG-ATHN` (authentication), `WSTG-ATHZ`
(authorization), `WSTG-SESS` (session management), `WSTG-INPV` (input
validation), `WSTG-ERRH` (error handling), `WSTG-CRYP` (cryptography),
`WSTG-BUSL` (business logic), `WSTG-CLNT` (client-side), `WSTG-DCVR`
(discovery).

## Scoring

CVSS 3.1 vector string for every finding's severity score; the relevant
CWE ID(s); and a note in the CISA KEV catalog if the underlying CVE is
already known to be exploited in the wild -- KEV membership is a
concrete signal for report prioritization, not just a nice-to-have
citation.
