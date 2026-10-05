---
title: "The Fragile Lock: Novel Bypasses For SAML Authentication"
url: "https://portswigger.net/research/the-fragile-lock"
vuln_class: "SAML / Authentication Bypass (XML Signature Wrapping)"
tech: "Ruby-SAML, php-saml, libxml2, REXML, Nokogiri"
bounty: 0
cve: "CVE-2025-66567,CVE-2025-66568"
source: "PortSwigger Research"
content_quality: "full"
date: 2025-12-10
---

## TLDR
Full authentication bypass in the Ruby and PHP SAML ecosystem via parser-level inconsistencies:
attribute pollution, namespace confusion, and a new class of **Void Canonicalization** attacks
-- bypassing XML Signature validation while presenting a valid SAML document.

## XML Signature Wrapping (XSW) core
Signature verification and assertion processing use separate modules/parsers. Inject a new
malicious Assertion into a legitimately signed response: the signature module validates the real
part, business logic consumes the injected assertion. Key enabler: `//ds:Signature` returns the
**first** occurrence anywhere in the document.

## Attribute pollution (namespace-agnostic getters)
libxml2's `xmlGetProp` ignores namespaces; Nokogiri `node['ID']` and PHP
`DOMNamedNodeMap::getNamedItem` return an attribute by simple name only. When `ID` and `samlp:ID`
collide, which is returned depends on attribute order:
```xml
<samlp:Response ID="1" samlp:ID="2">  <!-- xmlGetProp -> 1 -->
<samlp:Response samlp:ID="2" ID="1">  <!-- xmlGetProp -> 2 -->
```
REXML has the same flaw with the opposite selection order:
```xml
<Response ID="1" samlp:ID="2">       <!-- attributes['ID'] -> 1 -->
<samlp:Response ID="1" samlp:ID="2"> <!-- attributes['ID'] -> 2 -->
```
Poisoning:
```xml
<samlp:Response ID="attack" samlp:ID="ID">
  <Signature><Reference URI="#ID"/></Signature>
  <samlp:Extensions><Assertion ID="#ID"/></samlp:Extensions>
  <Assertion ID="evil"/>
</samlp:Response>
```
Workflow: signature module locates the target via `//*[@ID='id']` (namespace-agnostic); business
logic re-fetches the ID via a namespace-agnostic getter.

## REXML namespace confusion without DTDs
REXML treats `xml`/`xmlns` as regular attributes. `xml:xmlns='...'` can make a Signature visible
to Nokogiri but invisible to REXML's `//ds:Signature`:
```xml
<Signature xml:xmlns='http://www.w3.org/2000/09/xmldsig#'/>
<Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>
  <Child xml:xmlns='#anything'><Signature/></Child>
</Parent>
```
Injection points before the Signature that satisfy the XSD: `samlp:Extensions` and `StatusDetail`.

## Void Canonicalization (new class)
During digest calculation the parser removes the Signature; a fake Signature inside the Assertion
creates a recursive hash dependency. Exploit: the XML Signature Rec warns about relative URIs --
`xmlns:ns="1"` is a **relative namespace URI**, so libxml2 canonicalization errors, and
Nokogiri silently returns an **empty string**; the digest is then the hash of empty input
(`47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=` for SHA-256). A precomputed signature of the empty
string yields a "Golden SAML Response" that always passes validation.

## Getting a valid signature (when you don't have an assertion)
- SAML metadata (rarely signed, but `?sign=true` sometimes returns a signed version).
- Signed **error responses** to an invalid AuthnRequest (spec mandates a signed response).
- **WS-Federation metadata** -- almost always public for major IdPs.

## Affected / not affected
Vulnerable: ruby-saml 1.12.4 and prior (< 1.18.0), php-saml, xmlseclibs (< 3.1.4).
Not vulnerable: XMLSec library, Shibboleth xmlsectool.

## Real use case
Large SaaS: forged SAML Response + Gareth Heyes' "Splitting the Email Atom" parser bypass ->
create account -> full auth bypass.

## Tools
Burp extension: https://github.com/d0ge/XSW ; Golden-SAMLResponse sample:
https://github.com/d0ge/XSW/blob/main/samples/Golden-SAMLResponse.xml

## Defense
Strict XSDs with minimal extensibility, only process signed elements, keep libs patched, never use
email-domain suffixes as access control.
