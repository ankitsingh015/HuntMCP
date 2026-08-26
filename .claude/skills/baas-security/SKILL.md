---
name: baas-security
description: Backend-as-a-Service security testing for Supabase (PostgREST/RLS bypass, SECURITY DEFINER RPC cross-tenant leaks, Storage bucket policies, Auth signup abuse) and Firebase (Firestore/Realtime Database rules, anonymous-auth escalation, Storage bucket misconfig, Identity Toolkit abuse). Use whenever the target's frontend JS, APK, or config references supabase.co, firebaseio.com, firebaseapp.com, firestore.googleapis.com, identitytoolkit.googleapis.com, or embeds a Firebase/Supabase client SDK config object -- these are among the highest-yield, most-skipped surfaces in modern SPA/mobile bounty targets.
---

# BaaS security (Supabase & Firebase)

## When to use

Any target built on a modern JS framework (React/Vue/Next/Svelte) or a
mobile app that ships a client-side `supabaseUrl`/`anon` key pair or a
`firebaseConfig` object. This is not a gap in HuntMCP's existing coverage
of secrets-in-JS or cloud metadata -- `reconnaissance`'s JS-mining
checklist and `information-disclosure`'s cloud/datastore section already
tell you *how to find* the key. This skill is what to do once you have
it: both platforms hand every client an API credential by design, so the
key itself is never the finding -- the finding is what that credential is
still allowed to touch.

## Why the credential is not the vulnerability

Supabase's `anon` key and Firebase's Web API key (`AIzaSy...`) are meant
to be public -- they ship inside every page load and every APK. Reporting
"I found the anon key in the JS bundle" alone will get closed as
informational. The actual vulnerability is always on the server side of
that credential: a Postgres Row Level Security (RLS) policy that isn't
where the developer thinks it is, or a Firestore/Realtime Database rule
that's still in its permissive default. Confirm impact (data returned,
write persisted) before treating either credential as a finding.

## Supabase: PostgREST and Row Level Security

Supabase's REST API is PostgREST sitting directly on the project's
Postgres instance -- every `GET`/`POST`/`PATCH`/`DELETE` against
`https://<ref>.supabase.co/rest/v1/<table>` executes as a real SQL
statement, gated only by whatever RLS policies exist on that table for
the calling role (`anon` or `authenticated`, decoded from the JWT's
`role` claim).

- **Table has RLS enabled, zero policies defined**: PostgREST returns
  `200` with an **empty array**, not `401`/`403`. This looks identical to
  "the table is genuinely empty" -- don't conclude a table is safe just
  because it comes back `[]`; compare against an authenticated response
  or a row-count header (`Prefer: count=exact` returns the true count in
  `Content-Range` even when the row array itself is filtered to empty).
- **RLS not enabled at all**: PostgREST returns `42501 permission denied
  for table <name>` if grants are absent, or full data if grants exist --
  this is the "RLS was never turned on for this table" case, distinct
  from "RLS is on but misconfigured."
- **Schema discovery without credentials to a table list**: query a
  guessed table name (`profiles`, `orders`, `documents`) and read the
  `hint` field PostgREST returns on a miss --
  `{"hint":"Perhaps you meant the table 'public.customer_orders'"}` --
  which reveals real table names one guess at a time. Iterate against a
  wordlist of common SaaS nouns; each hint expands the wordlist.
- **Cross-tenant IDOR via a scope column**: the classic multi-tenant bug
  is a table where RLS correctly checks `auth.uid() = user_id` on
  `UPDATE`/`SELECT` but never checks `organization_id`/`tenant_id`. Pull
  your own row, `PATCH` your own `organization_id` to a target org's UUID
  (harvested from another user's public profile, a shared invite link, or
  sequential-looking org IDs), then re-query scoped tables -- this is the
  same "boundary is a parameter" pattern as the `access-control-and-idor`
  skill's mechanism 3, just enforced in Postgres instead of app code.
- **`rpc/` endpoints bypass RLS by design, not by accident**: a Postgres
  function marked `SECURITY DEFINER` and exposed at
  `POST /rest/v1/rpc/<function_name>` executes with the *function
  owner's* privileges (normally the Supabase service role), not the
  caller's -- meaning RLS on the underlying tables never applies inside
  it unless the function body re-implements its own `auth.uid()` filter.
  This is the single highest-value Supabase check: call every
  discoverable RPC (`get_dashboard`, `get_stats`, `search_users`,
  anything the frontend's JS calls via `supabase.rpc(...)`) with an
  ordinary `anon`/`authenticated` token and diff the result against what
  your own account should be scoped to. A dashboard RPC that aggregates
  "your" numbers but actually aggregates every tenant's rows is a
  cross-tenant data leak with no IDOR-style ID-swapping required at all.
- **`service_role` key leakage is total compromise, not RLS bypass**:
  decode the JWT payload of any Supabase key you find (`eyJhbGciOiJIUzI1
  NiIsInR5cCI6IkpXVCJ9...`, base64-decode the middle segment) and check
  the `role` claim. `anon`/`authenticated` are expected in client code;
  `service_role` in a JS bundle, mobile app, or Postman collection means
  RLS is bypassed entirely at the API layer for every table -- treat it
  as equivalent to a leaked database superuser password.

## Supabase: Storage

Supabase Storage access control is enforced by RLS policies on the
`storage.objects` table -- it's the same Postgres engine as the data
API, not a separate permission system. `GET /storage/v1/bucket` lists
bucket metadata (name, `public` flag) if a policy allows it;
`GET /storage/v1/object/list/<bucket>` lists objects inside one. A bucket
with `public: true` serves any object at
`/storage/v1/object/public/<bucket>/<path>` with **no auth check at
all**, regardless of what RLS says -- confirm the bucket's public flag
before treating a successful download as a policy bypass rather than
intended behavior. Test uploads (`POST /storage/v1/object/<bucket>/<path>`
with the `anon` key) separately from reads; a bucket can allow public
read while still requiring auth to write, or vice versa.

## Supabase: Auth abuse

- `POST /auth/v1/signup` with just `email`/`password` -- if it returns an
  `access_token` immediately (rather than requiring email confirmation),
  auto-confirm is enabled and you have an authenticated session for zero
  cost. Every table/RPC check above should be repeated from this session,
  not just the `anon` key, since some RLS policies gate on
  `auth.role() = 'authenticated'` without any further ownership check.
- `422` vs `200`/`400` on `/auth/v1/signup` is a user-enumeration oracle
  (email already registered vs. new) -- see `information-disclosure`'s
  enumeration-oracle section for the general pattern.
- `POST /auth/v1/recover` (password reset) and `POST /auth/v1/otp`
  (magic link / OTP) are worth the same reset-flow abuse checks as
  `auth-and-session`'s password-reset section -- Supabase's redirect
  target for magic links is a client-controlled `redirect_to` param in
  some project configs, which is an open-redirect-to-token-leak chain if
  the allowed-redirect list isn't locked down (`open-redirect` skill).

## Firebase: Firestore

Firestore access is governed entirely by its Security Rules, evaluated
per-request against the caller's auth context -- there is no separate
network ACL. `GET https://firestore.googleapis.com/v1/projects/<project>
/databases/(default)/documents/<collection>?key=<API_KEY>` returns
documents if the rules allow read for whatever auth state you present.

- **Rules written for "test mode"** (`allow read, write: if true;`,
  Firebase's own scaffold default that expires after 30 days but is
  routinely left in place or copy-pasted into new rule sets) expose the
  entire database with no token at all.
- **Anonymous auth as a rules bypass**: `POST https://identitytoolkit.
  googleapis.com/v1/accounts:signUp?key=<API_KEY>` with body
  `{"returnSecureToken": true}` and no email/password performs anonymous
  sign-in and returns a real `idToken`. Rules written as
  `allow read: if request.auth != null` read as "any signed-in user,"
  but anonymous sign-in satisfies that condition too -- if anonymous auth
  is enabled on the project (it usually is, since it's the SDK default),
  this converts a "requires login" rule into an unauthenticated bypass in
  one request.
- **Collection enumeration without knowing names**: `POST .../documents:
  listCollectionIds` against the database root (or a specific document
  path, for subcollections) returns every collection ID the caller's
  rules permit listing -- use it before guessing table names by hand.
- **Write and delete are separate rule branches**: a database that
  blocks `write` on a collection can still separately allow `create` or
  `update` -- test `POST` (create) and `PATCH` (update, Firestore's REST
  API uses field-mask query params for partial updates) independently
  rather than assuming one rule covers both.

## Firebase: Realtime Database

A structurally different product from Firestore, reachable at
`https://<project>.firebaseio.com/<path>.json`. New projects default to
requiring auth, so a bare `GET https://<project>.firebaseio.com/.json`
returning the full tree means the `.read` rule was explicitly changed to
`true` at some point -- check `/users.json`, `/messages.json`, and any
path name seen in the app's JS before concluding the whole tree is
empty, since Realtime DB rules can be scoped per child path rather than
global. `PUT`/`PATCH`/`DELETE` against a `.json` path test write access
the same way; a `.write: true` rule on even one deep path is enough for
a stored-data or defacement finding even if the root is otherwise locked
down.

## Firebase: Storage

Firebase Storage rules are a third, independent rule set from Firestore
and Realtime DB, but the same "still on the 30-day test default" failure
mode applies. List objects via
`GET https://firebasestorage.googleapis.com/v0/b/<project>.appspot.com/
o?key=<API_KEY>`, or through the underlying GCS JSON API directly
(`https://storage.googleapis.com/storage/v1/b/<project>.appspot.com/o`,
which doesn't require the Firebase API key at all if the bucket's IAM is
separately public). Download via `?alt=media` on a specific object path
once you have a name; test upload with the same API key before assuming
read-only exposure is the ceiling.

## Firebase: Identity Toolkit abuse

- `accounts:signUp` with `email`/`password` -- open registration if it
  succeeds without an invite/allowlist check upstream.
- `accounts:createAuthUri` with `{"identifier": "<email>", "continueUri":
  "http://localhost"}` returns `registered: true/false` and, for
  registered accounts, `allSignInMethods` -- a user-enumeration oracle
  that also fingerprints which OAuth providers (`google.com`,
  `facebook.com`, `password`) are linked to a given email, useful for
  targeting the identity-linking abuse in `identity-lifecycle-and-ato`.
- `accounts:sendOobCode` (password reset / email verification) -- same
  reset-flow checks as `auth-and-session`, plus watch for the
  `continueUrl` parameter being reflected into the reset email unchecked
  (open-redirect into a token-bearing link).

## Common config-leak endpoints worth checking directly

Beyond mining JS bundles (already covered by `reconnaissance`), both
platforms expose config through predictable, unauthenticated paths that
are worth a direct request even with no JS analysis done yet:
`https://<project>.firebaseapp.com/__/firebase/init.json` is
auto-provisioned by Firebase Hosting on every project and returns the
full client `firebaseConfig` object by design -- not a bug on its own,
but a fast way to get the API key and project ID without downloading and
grepping bundles first. Supabase has no equivalent public endpoint;
its URL/key pair always has to come from the client bundle, `.env`
exposure, or an APK's decompiled resources.

## Related skills

- `reconnaissance` -- JS-mining checklist finds the anon key /
  `firebaseConfig` in the first place; this skill starts once you have
  it.
- `information-disclosure` -- general cloud/datastore exposure and
  enumeration-oracle patterns this skill specializes for these two
  platforms.
- `access-control-and-idor` -- the cross-tenant `organization_id`/RPC
  pattern here is the same broken-authorization taxonomy, enforced in
  Postgres/security-rules instead of application code.
- `auth-and-session` / `identity-lifecycle-and-ato` -- signup, password
  reset, and account-linking abuse generalize directly to Supabase Auth
  and Firebase Identity Toolkit's equivalents.
- `open-redirect` -- both platforms' email-link flows (`redirect_to`,
  `continueUrl`) are redirect-parameter targets.
