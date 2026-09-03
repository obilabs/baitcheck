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
