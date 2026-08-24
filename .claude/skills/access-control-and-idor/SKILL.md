---
name: access-control-and-idor
description: Access-control technique list (IDOR, mass assignment, horizontal/vertical privilege escalation, GraphQL abuse, business-logic/money manipulation, race conditions) plus the explicit two-account IDOR testing procedure. Converted from master-pentest-prompt.md Phases 8/8.5. Use on any endpoint that returns or modifies user-specific data, and any multi-role application.
---

# Access control & logic

## When to use

Any endpoint keyed by a user/order/resource ID, any app with more than
one user role, any GraphQL API, and any feature that moves money
(cart/checkout/coupons/refunds).

## Access control & business logic techniques

- **IDOR everywhere**: user/order/invoice/project IDs -- numeric, UUID,
  base64, URL-encoded, hash, JWT `sub`. Iterate in parallel across
  resource types, not just one.
- **Mass assignment**: add `role`/`admin`/`verified`/`balance` fields to
  the JSON body or query string that the UI doesn't expose.
- **Horizontal and vertical privilege escalation**, both directions.
- **GraphQL**: introspection, batching (brute-force via a single
  request), aliases used for IDOR, query depth for DoS, field
  suggestion, data-source bypass.
- **API**: missing auth, version routing (`v1`/`v2` -- an old version may
  lack a fix the new one has), debug params, OpenAPI/spec leaks,
  idempotency-key abuse, pagination tamper.
- **Business logic (money)**: price/cart/quantity/currency/discount/
  coupon manipulation, payment bypass (null amount, negative quantity,
  currency swap), gift-card reuse, refund-policy abuse, loyalty-points
  inflation, referral abuse.
- **Race conditions**: checkout, coupon redemption, vote/like, withdraw,
  signup bonus, file upload (TOCTOU), 2FA verify, reward claim -- test
  with parallel requests.
- **Access control on**: admin APIs, internal endpoints, staging
  endpoints, cron/migration routes, file storage, dashboards, config
  viewers.

## IDOR / broken access control -- explicit two-account procedure

1. Create two accounts (or use two provided credential sets for each
   role): designate one as the **attacker** account and the other as the
   **victim**. Register a fresh account wherever a registration form
   exists; log in wherever a login exists -- break both as hard as
   possible.
2. Inventory every feature that returns sensitive info or modifies user
   data: profiles, orders, invoices, documents, projects, files,
   settings, messages, payment methods, addresses.
3. Intercept every sensitive request (proxy or curl replay) and swap the
   object identifiers (numeric ID, UUID, slug, base64, hash, JWT `sub`)
   from attacker values to victim values. If swapping IDs returns the
   victim's data or changes it, IDOR/BOLA is confirmed -- try both
   directions.
4. Widen the test: method swap (GET/DELETE/PUT on the same object),
   parameter pollution (`?user_id=A&user_id=V`), nested/deep-link IDs,
   GUID/UUID enumeration (date/base64 prediction), and sequential loops.
5. Replay every request across roles (user A vs. user B vs. admin) to
   find horizontal + vertical escalation, missing authorization, and BFLA
   (a lower role calling admin functions).
6. Assume the pattern exists elsewhere: an IDOR on `/api/user/ID` means
   `/api/order/ID`, `/api/file/ID`, and `/api/org/ID/members` are all
   worth testing too, across every resource type. Don't stop after one
   apparent immunity -- keep enumerating.

## The four IDOR mechanisms (from a survey of top disclosed HackerOne reports)

Every disclosed top-upvoted IDOR report reduces to one of four broken-
authorization patterns. Knowing which one you're looking at tells you
where to actually look, since the reference being swapped increasingly
lives in the request body (GraphQL variables, JSON fields), not the URL
-- a proxy-history review catches these where a URL-only fuzz pass won't:

1. **Your request, their object** (the most common pattern): the server
   correctly checks that you're authenticated and allowed to run the
   operation, but never checks that the object inside the operation
   belongs to you. Test by running every write operation (edit, delete,
   update, assign, tag) as attacker-account against victim-account's
   object IDs, swapping only the object reference in the body -- never
   the URL. Real precedent: a GraphQL mutation on HackerOne's own
   platform let any authenticated user delete another user's professional
   certifications by swapping one ID (HackerOne #2122671); Yelp's
   checkout endpoint let an attacker pay with a stranger's saved credit
   card by swapping `credit_card_id` (Yelp #391092).
2. **Two identifiers, never compared**: the server holds two facts about
   the request -- who's asking (session) and who the request is about
   (a body field, a sibling-domain cookie, an account-hierarchy
   relationship) -- and never checks they describe the same person. Test
   by making the identifiers disagree: attacker's session, victim's
   target identifier in the body, then send. A correct-looking secondary
   credential (even a password hash) in the request doesn't mean the
   session was authorized to use it. Real precedent: Mozilla's account-
   deletion API required the target account's email + password hash in
   the request body but never checked it against the *calling* session,
   so an attacker's session with a captured victim credential could
   delete the victim's account (Mozilla #3154983, high, 235 upvotes) --
   the largest bounty in the same survey (PayPal #415081, $10,500) was
   this same mechanism: adding another business's users as "secondary
   users" on your own account, since the API validated the caller and
   the operation but never the relationship between them.
3. **The boundary is a parameter**: an endpoint takes the trust boundary
   itself (an org ID, workspace/tenant name, subreddit) as an input
   parameter, and authentication alone is the only gate on it --
   authorization was never separately checked against that boundary.
   Test by enumerating scope-selector parameters (`organization_id`,
   `tenant`, `workspace`, `shop`) and pointing them at a scope you don't
   belong to; if the response size/content changes, follow pagination to
   the end for the full impact number. Real precedent: HackerOne's own
   `/bugs.json` search endpoint returned another organization's private
   report titles/states/severity given nothing but a valid `organization_id`
   and a logged-in session (HackerOne #2487889, critical).
4. **The reference that scales**: the ID format itself is predictable or
   resolvable enough to enumerate -- sequential integers, a username/email
   that an API will resolve into an internal ID for you, or a hash whose
   output length is short enough to collide. One swapped ID is luck; an
   enumerable reference turns it into every object in the database. Check
   whether creating two objects back-to-back produces sequential IDs, and
   base64-decode any GraphQL global ID (`gid://...`) to see what's
   actually inside it. Real precedent: a legacy CrowdSignal endpoint
   accepted sequential user IDs across a documented numeric range, and
   pulling a victim's email via the ID let an attacker log in as them
   with zero interaction (Automattic #915114, critical).

### Five questions to run on every endpoint

1. Whose object is in this request? (swap the reference, not the URL --
   catches mechanism 1)
2. What identifies the target, and does anything actually compare it to
   the session? (make them disagree -- catches mechanism 2)
3. Is the boundary itself just a parameter? (point it at a scope you
   don't own, follow pagination for the impact number -- catches
   mechanism 3)
4. Can the reference be predicted, decoded, or resolved from a
   name/email? (diff sequential IDs, decode base64 GraphQL IDs -- catches
   mechanism 4)
5. What does this object unlock one level up? Impact tracks what the
   object actually represents, not the bug class -- a leaked invoice
   (medium severity) paid a real bounty precisely because the data inside
   it was specific (card digits, address), while some criticals in the
   same disclosed-report survey carried no public bounty at all. Climb
   one level before writing up severity.
