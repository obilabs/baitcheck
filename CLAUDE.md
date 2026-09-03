# Baitcheck: notes for the agent working on this repo

Read `docs/RESEARCH.md` first, then `docs/DECISIONS.md`. This file is the short
version of what matters when writing code here.

## What this is
A Gmail add-on (Google Apps Script) that analyses the open email BEFORE the
user reports it as phishing, shows a plain-language verdict, and on confirm
sends a report packet (raw .eml + extracted indicators) to the security team.
Goal: fewer benign reports reaching the SOC, faster real ones. Made by Obilabs.

## Non-negotiables
- Works with no AI at all. AI is an optional second card, never required.
- Customer-deployed: the script runs in the customer's own Google Cloud
  project as an internal Workspace add-on. No Marketplace listing, no CASA.
- Never send email content to a third party unless the admin turned that on.
  Gemini via Vertex AI in the customer's project is the default AI path.
- Heuristic verdict card must render well inside the 30-second add-on limit
  (target under 3 s). AI goes in a separate card/action.
- Apache 2.0 add-on. The hosted dashboard is a separate, private repo later.
- The report packet JSON schema is the contract between add-on and any
  receiver; version it, document it in `docs/REPORT-PACKET.md`, keep it stable.

## Milestone 1 (first thing to build)
Heuristic verdict card + report packet, deployed to the owner's own Workspace
domain, no AI:
1. Contextual trigger on message open; read headers, body, links via the
   per-message token (`gmail.addons.current.message.readonly`).
2. Checks: SPF/DKIM/DMARC from Authentication-Results; display name vs sender
   domain; Reply-To / Return-Path mismatch; internal vs external; lookalike
   domain (confusables, edit distance vs org domain and a brand list); domain
   age via RDAP; link text vs href host, shorteners, IP literals; List-Unsubscribe
   and bulk cues; urgency / credential / payment / MFA phrases; risky
   attachment types.
3. Verdict card: one line ("Looks like a legitimate newsletter"), reasons as
   bullets, then buttons: Report, Unsubscribe instead (when applicable), Not sure.
4. Report: email the raw message as an .eml attachment plus a JSON packet to
   the configured security address (MailApp / gmail.send, sensitive scope only).
5. Admin settings via Script Properties: security address, org domains,
   allowlisted senders, and a Dashboard URL + token. With no dashboard the
   add-on is standalone (heuristics, optional Vertex Gemini in the customer's
   project). With a dashboard, AI configuration lives there and the dashboard
   performs AI analysis for the add-on (`POST /api/v1/analyze`); the add-on
   never holds AI keys in connected mode.
Definition of done: installed on the owner's domain, verdicts on 20 real emails
reviewed and reasonable, one report received with intact headers.

## Later milestones
Web Risk URL lookup (customer project, 100k/month free) → AI second-opinion
card (Vertex, or BYO key for Claude/OpenAI) → admin allowlists and user
feedback loop → simulation-header awareness → hosted dashboard (separate repo).

## Tooling notes
- Development machine is a Mac with Apple's Python 3.9 and no Node by default.
  `clasp` (Apps Script CLI) needs Node; install via Homebrew (`brew install node`)
  and `npm i -g @google/clasp` when starting. Keep `.clasp.json` out of git.
- Prefer plain Apps Script (V8 runtime, JavaScript) with a `src/` layout pushed
  by clasp; unit-test pure heuristics in Node without the Apps Script runtime.
- Commit messages end with the Co-Authored-By trailer the harness provides.

## Owner context
The owner previously ran KnowBe4's button, learned it was "included" not free
when changing training platforms, and built a crude replacement in a day with
Claude Opus. This is the from-scratch, done-properly version. No revenue is
intended from the add-on; the hosted dashboard is the only planned paid piece.
