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
   directions. Once you have more than a couple of object ids per
   endpoint, hand-testing each one doesn't scale -- `mcp__idor-mcp`
   `sweep_idor(url, object_ids, owner_cookie_header/owner_bearer_token,
   other_cookie_header/other_bearer_token)` automates exactly this loop:
   given a URL template with an `{id}` placeholder and a list of ids
   known to belong to one account, it fetches every id once per account
   and classifies the pair (PROTECTED/LEAKED/AMBIGUOUS/DIFFERENT/
   OWNER_BASELINE_FAILED -- the last one is the tool's own way of
   flagging "this account has no real data for this id," the same empty-
   test-account problem this procedure's step 1 exists to avoid). A
   LEAKED verdict is a strong candidate for manual confirmation, not an
   automatic CONFIRMED finding.
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

## Standalone read-IDOR pays Low-Medium -- chase the paired write

A read-IDOR alone ("I can see victim's data") is worth far less than the
same reference swapped against a state-changing endpoint ("I own victim's
account"). When a read-IDOR confirms, immediately check whether the same ID
is also accepted by:

1. **Email/password-reset endpoints** -- `PUT /api/users/{victim_id}/email`
   with no ownership check, then trigger password reset -> reset link lands
   on the attacker's new email -> silent ATO with no email-change
   notification (the API path skips the UI's own audit log).
2. **Refund/withdraw/transfer endpoints** -- pair a first IDOR that leaks
   `order_id`/`account_id` values with a second IDOR on the money-movement
   endpoint itself; direct financial impact, not just a data read.
3. **Team/role-membership endpoints, combined with mass assignment** -- an
   IDOR'd `POST /api/teams/{victim_team}/members` that also accepts an
   unfiltered `role` field in the body escalates a horizontal IDOR straight
   to admin on the victim's team.
4. **Soft-delete without session invalidation** -- if "remove member" flips
   an `active=false` flag but doesn't revoke the session/PAT, a token
   captured before removal keeps working after -- a *temporal* IDOR the
   access-control policy table doesn't catch.

Hunt for both halves of the pair -- the write half usually shares the exact
same missing-ownership-check root cause as the read half you already found,
so it's often faster to find than the first one was.

## Mass assignment -- encodings that slip past field-name filters

Many mass-assignment defenses only block the literal field name at the
top level of the JSON body -- they miss the same field reachable through a
different encoding. Test every sensitive field (`role`, `isAdmin`,
`verified`, `balance`, `tier`) through each of these shapes before
concluding a field is actually filtered:

- **Dot-path notation**: `{"profile.is_admin":true}`, or form-encoded
  `user.role=admin` -- ORMs that flatten dotted keys into nested updates
  (Mongoose especially) bind straight through a filter that only inspects
  the top-level key.
- **Bracket notation**: `user[role]=admin` / `user[is_admin]=1` in a
  form-urlencoded body -- common PHP-framework parsing turns this into a
  nested array the allowlist never inspects.
- **Array/object wrapper**: `{"user":{"name":"test","admin":true}}` --
  wrapping the sensitive field inside a nested object the endpoint also
  accepts (Rails `params.permit`, Laravel `$request->all()`) skips a
  filter written only for flat top-level keys.
- **JSON Patch / JSON Merge Patch**: `[{"op":"replace","path":"/role",
  "value":"admin"}]` against `Content-Type: application/json-patch+json`,
  or `{"role":"admin"}` against `application/merge-patch+json` -- patch-
  format endpoints frequently run a different (weaker) deserializer than
  the main create/update handler, so a field blocked on `POST` can go
  straight through on `PATCH` once the content-type switches to a patch
  format.
- **Batch/array endpoints**: submit an array of objects to a bulk-update
  endpoint (`PUT /api/users/batch {"users":[{"id":"me","name":"test"},
  {"id":"VICTIM_ID","role":"admin"}]}`) -- per-item authorization is
  commonly skipped when the framework only authorizes the batch request as
  a whole, not each element inside it.
- **Duplicate keys**: `{"name":"test","role":"user","role":"admin"}` --
  parser differentials between a WAF/proxy (which may read the first
  occurrence) and the application (which may read the last) let a blocked
  value through.

Test every naming convention (`is_admin`/`isAdmin`/`IsAdmin`) against every
shape above -- a framework that rejects one combination often accepts
another because the allowlist and the parser were written by different
people at different times.

## Named IDOR composition chains -- more disclosed-report precedents

Two further compositions, beyond the paired-write patterns above, turn a
single IDOR into a materially bigger finding:

- **IDOR download + filename-controlled response header -> stored XSS ->
  session theft**: a file/document download endpoint is IDOR'd (any
  user's file given its ID), and the same endpoint reflects the
  uploader-controlled filename into `Content-Disposition: attachment;
  filename="..."` without stripping quotes or newlines. An attacker
  uploads a file with a filename crafted to break out of the header and
  inject a script tag; when the victim (or an admin reviewing the file)
  opens the download link, the injected script runs in the response
  context and exfiltrates the session. Neither the IDOR nor the header
  injection is critical alone -- the chain is. Seen across disclosed
  SharePoint, GitLab attachment, and SaaS-export download endpoints.
- **IDOR via GraphQL Relay global ID + nested-relation traversal -> mass
  cross-tenant extraction**: the top-level `node(id:)` resolver correctly
  authenticates and authorizes the requester for the object it directly
  resolves, but nested relations hanging off that object (`orders`,
  `paymentMethods`, `invoices`) don't re-check ownership against the
  resolved parent. Decode the base64 global ID (`gid://shopify/Customer/
  <n>` or a similar `type:id` pattern) to recover the numeric ID, then
  walk it: `node(id:"<victim_gid>") { ... on Customer { email orders {
  totalPrice paymentMethods { cardLast4 } } } }`. Iterating the decoded ID
  turns one authorized query into a walk of the entire customer base.
  Real precedent: Shopify Billing IDOR (HackerOne #2207248, $5,000);
  HackerOne's own PolicyPageAssetGroup IDOR (HackerOne #1618347,
  $25,000).
- The team-membership + mass-assignment role-escalation chain above has
  real bounty precedent too: Shopify's undocumented `fileCopy` mutation
  (HackerOne #981472, $2,000, 2020) and Stripe's
  `UpdateAtlasApplicationPerson` cross-tenant mutation (HackerOne
  #1066203, 2020) both reduce to the exact same root cause -- an IDOR'd
  membership/person-update endpoint that also accepts an unfiltered role
  field in the body.

## Business logic: disclosed price-tampering and coupon-race precedents

Real bounty precedent for the money-manipulation bullet above, each with
measurable financial impact:

- **Stripe -- fee-discount race redemption** (HackerOne #1849626, $5,000,
  2023): Stripe Support applied a one-time $20,000 fee-credit; the
  researcher captured the "accept-discount" POST and replayed it 30x in
  parallel via Turbo Intruder, each parallel acceptance crediting the
  account again. Root cause: no idempotency key and no unique constraint
  on `(account_id, discount_id)` -- $600,000 of fee-free transactions
  accrued before the fix.
- **Upserve/OLO -- negative-quantity price manipulation** (HackerOne
  #364843, 2018): `POST /api/order {"items":[{"id":1,"qty":1,"price":50},
  {"id":2,"qty":-3,"price":50}]}` computes a negative order total that
  floors to ~$0 at payment capture while the food still fulfills. Root
  cause: server multiplies `qty * price` with no `qty >= 1` guard.
- **Krisp -- pay-less-per-seat via PUT tampering** (HackerOne #1446090,
  2021): `PUT /v2/seats` reads a client-supplied `price` field instead of
  looking the price up by `plan_id` -- setting `price=1` drops a
  100-seat, $60/seat subscription to $1/seat. Same root cause as generic
  mass assignment, just landing on a billing field instead of a role
  field.

**Phone-ownership verification bypass**: when a flow accepts a phone
number and "verifies" it by sending an OTP, check whether the platform
grants trust the moment the number is *submitted* rather than waiting for
OTP *confirmation* -- e.g. a callback-number field that's immediately
treated as verified in downstream logic (fraud scoring, 2FA fallback,
contact display) before the OTP round-trip ever completes. Submitting a
victim's real phone number lets an attacker borrow their verified status
without ever proving control of the phone.

## Read-protected, write-open: an access-control pattern to check on every endpoint

Don't assume that because `GET /resource` correctly scopes results to the
caller, the write verbs on the *same* resource do too. A common asymmetry:
authorization gets implemented once for reads (a `WHERE user_id = ?`
clause, an RLS policy, a resolver check) and never mirrored onto
`PATCH`/`PUT`/`POST`/`DELETE` on the same object -- because the write path
was added later, by a different developer, or reaches the data through a
different code path (a raw ORM update vs. a scoped query builder).
Concretely: confirm you can only read your own record, then try the exact
same object reference against every write verb the endpoint accepts; a 200
with your data changed -- or worse, a filter like `?user_id=neq.<self>`
returning other users' rows -- means the read-side check was never ported
to the write side. This is a distinct failure from the mass-assignment and
IDOR patterns above: the object reference can be entirely correct (it's
your own object) and the vulnerability is still there, in the missing
write-side authorization gate itself. BaaS platforms (Supabase/PostgREST
row-level security, Firebase security rules) are an especially common
place this shows up, since read and write authorization are configured as
separate rule sets that are easy to leave out of sync -- see the dedicated
`baas-security` skill for that platform-specific depth.
