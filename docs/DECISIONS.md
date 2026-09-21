# Decisions

Dated so later readers know what was known at the time.

## 2026-09-03 Name
"Baitcheck": check the bait before you bite. Chosen over Phish-* names to avoid
the crowded namespace (KnowBe4, Cofense, Proofpoint). Domain and trademark not
yet checked.

## 2026-09-03 Licence
Add-on: Apache 2.0. Reason: it must be freely usable by businesses because they
deploy it into their own Google Cloud projects; Apache adds an explicit patent
grant and reserves the Obilabs name and logo. A fork does no harm since the
add-on is the free part by design. If outside contributions arrive, require
DCO sign-off (GitHub setting + CONTRIBUTING line) rather than a CLA.

## 2026-09-03 Dashboard is a separate, private repository
The hosted dashboard for security teams (reports per user, precision, top
spoofed brands) is the only planned paid piece. Keep it in its own repo,
private at first: different stack and release cadence, customers deploying the
add-on must not need it, and opening later is trivial while closing is not.
If opened later, AGPL is the standard choice for a hosted product. Create the
repo only when there is code for it.

## 2026-09-03 Contract between add-on and receivers
The report packet (JSON sent with the raw .eml) is the interface. Versioned
schema documented in `docs/REPORT-PACKET.md` (to be written with milestone 1).
This keeps "works without the paid dashboard" true.

## 2026-09-03 Distribution model
Customer-deployed internal add-on, not a Marketplace listing. Avoids OAuth
verification and the annual CASA assessment, allows restricted scopes if ever
needed, and makes Vertex AI and Web Risk one-project enablement.

## 2026-09-03 AI
Off by default. Default provider when on: Gemini through Vertex AI in the
customer's project (no API key, Cloud data terms, ~$0.002 per email). Optional
bring-your-own key for Claude or OpenAI. Note: no "Gemini via Workspace
licence" API exists; do not promise it.

## 2026-09-03 Two modes: standalone and connected
The add-on's admin settings have a "Dashboard URL" and token. Empty means
**standalone**: heuristics, plus optional Gemini through the customer's own
Google Cloud project, configured in the add-on. Set means **connected**: all
AI configuration (provider, keys, prompts, headers-only vs full body) lives in
the dashboard, and the dashboard performs the AI analysis on the add-on's
behalf and returns the verdict. Keys never sit in Apps Script; one admin screen
controls every user. Connected mode also brings outcomes, rules sync and the
report queue. Consequence to disclose: in connected mode the reported
message's content is sent to the dashboard, which is in-house when self-hosted
and Obilabs-operated when hosted.

## 2026-09-13 Milestone 0: copy-paste Apps Script
Ship the smallest useful version before the packaged add-on: files pasted into
a user's or admin's own Apps Script project. It supersedes the internal
PhishLens prototype (code brought over as fresh files, no history).
- Evidence, not verdict: the card lists what it noticed and neutral context;
  the person decides. The packet's `verdict.label` is only `suspicious` or
  `unknown`.
- No data leaves the mailbox on open. PhishLens sent every link to URLhaus
  automatically; Baitcheck only looks links up when the user presses "Check
  links", only with services the admin listed and keyed, and caches results in
  the per-user cache (not the script cache, which is shared between users).
  Tests fail if the open path calls UrlFetchApp.
- Scopes: `gmail.addons.execute`, `gmail.addons.current.message.readonly`,
  `gmail.send`, `script.external_request`. Dropped `script.scriptapp` (unused).
  No "move to trash" option: it needs `gmail.modify`, a restricted scope.
- Lookup services: URLhaus (needs a free abuse.ch Auth-Key since 2025), Google
  Web Risk, Google Safe Browsing, VirusTotal, all bring-your-own key. Hosts
  pinned in the manifest's `urlFetchWhitelist`.
- Reporter address is not read (would need another scope); the report email's
  sender identifies the reporter.

## 2026-09-13 Free add-on everywhere; the paid product is the hosted service
Supersedes "customer-deployed internal add-on, not a Marketplace listing" (2026-09-03).
The add-on stays free and Apache 2.0, including a free public Google Workspace
Marketplace listing. The current scopes are sensitive, not restricted, so a listing
needs Google's app verification but not a CASA assessment. There is no paid add-on
edition: a licence check in Apache code can be removed by anyone, and Marketplace
does not take payments. Customer deployment stays supported.

What is paid: a hosted triage queue with feedback to the reporter, monthly evidence
reports (report rate, share harmless, time to triage), managed rollout and support.
Indicative pricing $1-3 per user per year or flat tiers for schools and nonprofits.
What must stay free: the add-on, every check, the report packet format, the rules and
brand lists, a self-hosted receiver, and "nothing leaves the mailbox on open".
Research: `docs/RESEARCH-PAID-EDITION.md`.

## 2026-09-16 The report email: opaque .eml, triage order, suggested actions
From the first real install. Three changes to what the security mailbox receives:
- **The `.eml` is attached as `application/octet-stream`, not `message/rfc822`.**
  Google Groups and several mail clients render an rfc822 part inline, so the
  reported message was displayed inside the security mailbox: remote images and
  tracking pixels loaded from the security team's network and a live link sat one
  click from the reader. The filename stays `reported-message.eml` and the packet
  now carries `eml.content_type`; a receiver that parses the part keys on those,
  not on the MIME type. Trade-off accepted: tooling that auto-parses rfc822 parts
  must look at the filename instead.
- **The body follows the triage order**: what happened, what Baitcheck noticed,
  the decision facts (display name and address apart, Reply-To, Return-Path,
  SPF/DKIM/DMARC, deduplicated link domains, attachment hashes), suggested
  actions, what is attached, and what Baitcheck did not do. Short enough to read
  on a phone; the JSON packet carries the full structure.
- **Suggested actions with Admin console links** (block the sender address, block
  the sending domain, find out who else received it, do nothing), each with its
  reason. They are suggestions to a person, never instructions, and never imply
  Baitcheck can act: it cannot, and will not ask for the scope that would let it
  (north-star D-040). Console links are verified against Google's own help pages
  rather than invented, and the search-and-remove line names the editions Google
  lists for the investigation tool instead of promising a button.

## 2026-09-13 AI uses a key the organisation supplies
The admin can add their own Claude, Gemini or OpenAI API key; AI analysis then runs
with the organisation's own account and terms. Vertex AI in the customer's Cloud
project is not required. Rules for it:
- Off by default. The evidence card always renders first and never waits for AI.
- AI runs only when the user asks (or the admin turns on analysis for reports), never
  silently on open.
- The admin screen says which provider receives the message content and links that
  provider's data terms; free-tier keys may allow training on content, and the UI
  says so.
- The AI result is labelled as an opinion next to the evidence, never a verdict.

Open design question: in a customer-deployed script the key lives in Script
Properties (only people who can edit the script can read it). A public listing runs
in ObiLabs' Cloud project, so Script Properties would be shared across every
organisation; per-organisation settings there need another home (per-user
properties, or organisation settings held by the hosted service). Decide before the
listing ships.

## 2026-09-20 The original is zipped, because a MIME type is not enough
The 2026-09-16 fix did not work, and the second real test showed why. Gmail's
send API **re-types an attached `.eml` by sniffing its contents**: an attachment
declared `application/octet-stream` and named `reported-message.eml` arrived at
the security mailbox as `Content-Type: text/html` with **no filename**, and
Google Groups rendered the reported message inline anyway — the exact failure the
change was meant to prevent. Confirmed in the raw message ("Show original") of a
report sent on 2026-09-20.

So the original now travels **inside `reported-message.zip`**. Nothing renders the
contents of a zip, and zipping a phishing sample is the usual practice between
security teams. The packet keeps `sha256` and `size` of the `.eml` itself, so a
receiver can verify what is inside, and adds `archive` and `file`.

Superseded: the `application/octet-stream` part of the 2026-09-16 entry. The rest
of that entry (triage order, suggested actions, what Baitcheck did not do) stands.
