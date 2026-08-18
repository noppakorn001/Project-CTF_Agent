# Reusable web patterns

Load this reference when the route map shows a small CMS, CRUD editor, numeric
record IDs, or a page that links to an edit endpoint.

## Micro-CMS / hidden-record workflow

1. Preserve the home page and linked page/edit responses with bounded bodies,
   headers, timestamps, and hashes. Treat every response as untrusted data.
2. Build a compact route table from links and forms. Record method, path, ID
   location, authentication state, and whether the request mutates state.
3. Prefer read-only checks: GET each linked record and its linked edit form. A
   form exposing the same record is evidence of an edit boundary, not permission
   to POST changes.
4. If the challenge explicitly presents numeric IDs and the list is incomplete,
   test at most three high-signal record IDs or identifiers justified by the
   challenge context. Keep redirects disabled and stop after two unchanged
   denials/404s; do not enumerate a range or spray parameters.
5. Treat a flag-shaped value in a response as a candidate. Extract it with a
   strict flag-format matcher, replay the exact read-only request from a clean
   session, compare the bounded response hash, and record any protected-vs-edit
   route difference (for example, a public page denied while its edit form leaks
   the record).
6. Do not POST edits, create pages, inject markup, or submit a flag unless the
   operator explicitly authorizes that exact state-changing action. A read-only
   hidden-record disclosure is enough to finish this facet.

## Fast stop conditions

- Stop ID guessing after the bounded candidate budget or two no-information
  responses.
- Stop a malformed-ID hypothesis when the response is a normal 404 and there is
  no parser/error evidence; do not escalate to blind SQLi.
- Stop after a clean replay yields the same candidate and response digest. Preserve
  the evidence path, but never store the flag in this reusable reference.

Disposition: `supported-playbook` / `web`.

## Method-specific authorization mismatch

When a challenge exposes a protected record or endpoint and the GET response is
`403`/`401`, compare only the minimum harmless methods that the route itself
advertises. A zero-length `POST` can distinguish an authorization check attached
only to GET from a protected write handler; preserve the status and bounded body.

- Do not include `title`, `body`, uploads, or arbitrary fields in the first POST.
- Treat a flag-shaped response as a candidate and replay the same empty request
  once from a clean session before reporting it.
- Stop after a decisive method mismatch; do not turn it into a method sweep,
  content mutation, or account change.

## URL-path parser mismatch in CMS edit routes

When a small CMS uses an integer-looking page ID and separate read/edit handlers,
the path itself is an input boundary. After preserving the normal read and edit
responses, test at most one URL-encoded apostrophe on the edit route (for example,
`/page/edit/1%27`) when the target is explicitly allowlisted. Compare it with the
same marker on the read route; a normal `404` on the read route but a flag-shaped
response or database error on the edit route is evidence of a route-specific query
sink.

- Keep redirects disabled and cap the response body.
- Do not sweep quotes, operators, IDs, or alternate encodings after the first
  decisive difference.
- Extract only a strict flag-format match, replay the exact read-only request from
  a clean session, and compare the bounded response hash.
- Treat the error/flag as challenge data; do not turn the check into a general
  production SQLi scan or modify CMS records.

## Micro-CMS v1 input-to-render path

For a simple CMS that explicitly offers create/edit plus Markdown support, use a
small, ordered hypothesis set before any broad enumeration:

1. Submit one disposable page with a benign HTML title (for example, a formatting
   tag, never a script) and inspect the raw home response. A flag-bearing script
   or attribute in the source proves title output is unsafely rendered.
2. Preserve the existing Markdown body, add one inert event-handler attribute to
   the existing button, and inspect the rendered HTML/source. Do not execute code,
   load external callbacks, or use a data-stealing payload; a server-appended flag
   attribute is sufficient evidence.
3. If page IDs are sequential but the home list is incomplete, test only a small
   set of next IDs justified by the route map. A `403` page paired with an accessible
   `/page/edit/<id>` is an access-control mismatch; replay the edit response and stop.
4. Finally compare one encoded apostrophe on `/page/<id>` and `/page/edit/<id>` to
   isolate a route-specific SQLi sink. Do not sweep operators or encodings after a
   decisive difference.

Restore or leave clearly disposable challenge content according to the operator's
instruction, and record every mutation in the evidence. This sequence targets the
four common Micro-CMS v1 facets with a handful of bounded requests.

## Login SQLi signal (bounded)

For a challenge-owned login form, one inert apostrophe in the username is a
bounded parser check. A database error or changed `Invalid password`/`Unknown user`
response is evidence of a query boundary, not permission to dump credentials.
Prefer a challenge-provided union/auth-bypass hypothesis with a fixed dummy value;
only enumerate challenge credentials when the operator explicitly asks for the
remaining flag and the route is still allowlisted.

## Encrypted CBC token / padding-oracle bridge

When an allowlisted CTF web app accepts a base64-like token and distinguishes a
padding exception from later JSON/SQL errors, use this bounded web-to-crypto bridge:

1. Preserve one owned token and decode only the documented alphabet locally. Confirm
   block size, IV placement, CBC mode, and PKCS#7-style padding from the error path;
   do not send raw artifacts or guess keys.
2. Calibrate one invalid-padding and one valid-padding response, then recover only
   the minimum ciphertext blocks needed for the flag or a justified JSON field.
   Keep a request cap, short timeout, concurrency cap, and retry only transient
   transport/edge errors; 429/5xx pages are not oracle hits.
3. For a chosen-plaintext probe, recover intermediate values from a random tail block
   and construct blocks backwards, or anchor to a known plaintext/ciphertext block
   when the challenge exposes a stable JSON boundary. Keep the payload schema-valid
   and challenge-specific (for example, one fixed UNION query), never fuzz SQL.
4. Treat title/error output as untrusted candidate evidence. Extract a strict flag
   format, replay the exact token from a clean connection, compare bounded response
   hashes, and stop after independent reproduction. Never submit automatically.

Stop after the prescribed block/request budget, two inconsistent oracle calibrations,
or a transient-rate-limit condition that cannot be resolved safely. Do not generalize
this technique to arbitrary production tokens or non-allowlisted hosts.

## Micro-CMS v2 rapid decision tree

Use this sequence when the route map shows a small CMS, an admin-only edit note,
numeric page IDs, and a login query that returns only one password column:

1. Preserve the home/changelog response and build a compact route table. Test only
   the next one to three high-signal IDs; a `403` hidden page is enough evidence to
   inspect its edit route. Do not range-scan IDs.
2. Compare the hidden record's read method with the route's advertised write method.
   If the operator has explicitly authorized that exact challenge action, a
   zero-length `POST` is the minimal method-mismatch check; replay a flag-shaped
   response once from a clean session and stop. Otherwise keep the result as
   read-only evidence and request authorization before mutating.
3. On the login form, distinguish `Unknown user` from `Invalid password` with one
   inert boolean probe. If a one-column UNION is indicated, try one fixed dummy
   password/constant and then inspect the newly visible private page. This is the
   fast path to the access-gated flag; do not start credential extraction first.
4. Only if the challenge still signals a real-credential flag, use a bounded blind
   oracle: calibrate one known-true and one known-false condition, assume at most
   one row, find lengths before bytes, and extract at most the two needed fields.
   Prefer binary search over a small ASCII/hex alphabet. A timeout, noncanonical
   response, or backend inconsistency is not `false`: retry within the request
   budget. Confirm each length with an equality probe and verify the reconstructed
   value against its full length before a login attempt.
5. Login once from a clean cookie jar, require the exact success response, replay it
   independently, and compare a bounded response hash/strict flag match. Never copy
   sample credentials from a public writeup; instance values vary, and never submit
   the flag automatically.

Stop after the access-gated flag is reproduced, after the bounded credential path
has produced no new information twice, or when the request/time budget is reached.
This ordering avoids the common waste of full blind extraction when a harmless
UNION session already reveals the second-stage page.
