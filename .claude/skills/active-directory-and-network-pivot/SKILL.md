---
name: active-directory-and-network-pivot
description: Active Directory, Windows, and internal-network post-exploitation pivot techniques -- Kerberoasting/AS-REP roasting/pass-the-ticket/golden-silver tickets, NTLM relay and pass-the-hash, BloodHound path-to-DA analysis, ACL abuse, a default-port probe checklist for pivoting from a web box, and LLMNR/NBNS/mDNS poisoning. Converted from master-pentest-prompt.md Phase 35. Use only after landing a shell or network foothold with AD/internal-network pivoting explicitly in scope.
---

# Active Directory / Windows / network (post-exploit pivot)

## When to use

Only after a shell or internal-network foothold is already established
and lateral movement / AD attack surface is explicitly in scope for the
engagement -- this is deep post-exploitation territory with a much
larger blast radius than web testing; confirm scope before using any of
it, separate from confirming shell access itself was in scope (see the
`post-exploitation` skill's scope note, which applies here too).

## Kerberos attacks

Kerberoasting, AS-REP roasting, pass-the-ticket, golden and silver
tickets (forged via a compromised `krbtgt` hash), Unconstrained
Delegation abuse, shadow credentials via `msDS-KeyCredentialLink`, ADCS
ESC1 through ESC8 certificate-template abuse, and GPO poisoning.

## NTLM attacks

Pass-the-hash, overpass-the-hash, DCSync via MS-DRSR, SMB relay
combined with PrinterBug/RPC coercion (PetitPotam), and Responder for
LLMNR/NBNS credential capture.

## Path analysis

BloodHound for shortest-path-to-Domain-Admin analysis, which routinely
surfaces certificate-template abuse paths that aren't obvious from
manual enumeration alone.

## ACL abuse

`GenericAll`/`WriteOwner`/`GenericWrite` rights misconfigured on AD
objects -- e.g. an over-permissioned SMS-admin-ops account that can be
used to escalate.

## Default-port probe checklist (pivoting from a web box)

Check each of these before assuming a box is a dead end:

| Port | Check |
|---|---|
| 22 | SSH keys left on disk, weak creds |
| 445/139 | SMB null session (`enum4linux -a`) |
| 21 | FTP anonymous login |
| 23 | Telnet |
| 3389 | RDP weak creds |
| 161/162 | SNMP `public`/`private` community strings |
| 8080/8443 | Alternate web ports |
| 3306 | MySQL `root:root` |
| 27017 | MongoDB open with no auth |
| 6379 | Redis no-auth |
| 11211 | Memcached |
| 9200 | Elasticsearch open |
| 5900 | VNC with empty password |
| 2375 | Docker exposed without TLS |
| 8888 | SSRF-friendly proxy tooling (DejaVu-class CVEs) |

For every discovered service, resolve version -> CVE via `searchsploit`
or nuclei templates, and check for credential reuse across device-panel
portals (routers, cameras, IPMI often keep vendor defaults).

## Poisoning

IPv6 neighbor discovery plus mDNS/LLMNR/NBNS poisoning, when working
within an internal-network lab scope.

## Cloud pivot

An overly-permissive AWS CLI profile found on a compromised box, or a
`kubectl` config granting broader cluster access than the box itself
should have.
