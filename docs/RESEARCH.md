# Pre-report phishing check for Gmail: research (2026-09-03)

Goal: a Gmail add-on (Google Apps Script) with a "Report phishing" button that
analyses the open email FIRST, tells the user what it looks like, and only then
reports it, to cut the 80-85% of user reports that are benign. Works without AI,
better with AI. Admin-configurable AI (Gemini, Claude, OpenAI).

## 1. Platform facts (Gmail add-ons, Apps Script)

- Contextual trigger fires when a message is opened; the add-on gets a
  per-message access token and can read subject, from, body, headers, raw MIME
  (`getRawContent`, `getHeader`, `getReplyTo`, `getAttachments`).
  https://developers.google.com/workspace/add-ons/gmail/extending-message-ui
- Scopes: `gmail.addons.current.message.readonly` and `gmail.send` are
  "sensitive" (3-5 day OAuth review); `gmail.modify`, `gmail.readonly` are
  "restricted" (annual CASA security assessment, ~$800-1,200/yr Tier 2 lab).
  Deleting, trashing or labelling the reported mail needs a restricted scope.
  https://developers.google.com/workspace/add-ons/concepts/workspace-scopes
  https://support.google.com/cloud/answer/13464321
- No API triggers Gmail's native "Report phishing" (open request since 2024).
  https://issuetracker.google.com/issues/329687280
- Limits: 30 s per card render or action; UrlFetch 100k/day/user.
  https://developers.google.com/apps-script/guides/services/quotas
- Distribution: (A) vendor Marketplace listing needs OAuth verification, and
  CASA if any restricted scope; (B) customer-deployed (script in the customer's
  own GCP project, Internal consent screen, private listing or admin push)
  needs no verification, no CASA, allows restricted scopes, bills AI to the
  customer. https://support.google.com/cloud/answer/13464323

## 2. Gemini without API keys: partly

- No "Gemini for Workspace licence" API exists for add-ons; a Workspace Gemini
  seat does not give scripts inference. Checked, not found as of Sept 2026.
- What exists: the Apps Script Vertex AI advanced service. Needs a GCP project
  with billing and Vertex enabled; auth is OAuth (user token with
  `cloud-platform` scope, or a service account), so "no API key" is true but
  "no setup" is not. https://developers.google.com/apps-script/quickstart/vertex-ai
- Model (B) above makes this natural: the script already lives in the
  customer's project, so Vertex is one checkbox and one IAM group away.
- Data terms: Vertex prompts are not used for training and fall under the
  Cloud DPA; note Workspace's own Gemini commitments do NOT cover third-party
  add-ons, so the privacy story must cite Cloud terms.
  https://services.google.com/fh/files/misc/genai_privacy_google_cloud.pdf
- Cost: ~$0.002 per email analysis on Gemini Flash; negligible.
- AI Studio keys: free tier is heavily cut and unpaid usage may be reviewed or
  used for improvement; only paid/billed projects get the DPA.
  https://ai.google.dev/gemini-api/terms

## 3. Competitors and the gap

| Product | Gmail? | Pre-report verdict? | Price | Notes |
|---|---|---|---|---|
| KnowBe4 Phish Alert Button | yes, free | no (PhishER Plus after report, ~$14-18/user/yr) | free button | asks full Gmail access; 6M installs |
| Hoxhunt | yes | yes ("Instant Feedback", seconds after report) | ~$10-30/user/yr | says 80-85% of reports are benign |
| Proofpoint Report Suspicious | yes | after report, in their cloud | $25-70/user/yr PSAT | |
| Cofense Reporter | yes | no | ~$10/seat/yr + Triage | outage complaints |
| Microsoft Report Message | M365 only | automatic verdict email (Defender P2) | included | the benchmark Google lacks |
| Google native button | yes | no | included | admin "User reports" panel only on Enterprise Plus / Frontline Plus / Education |

Gap: nobody on Gmail gives a verdict BEFORE the click, and Business Starter /
Standard / Plus admins get almost nothing back from native reports.

## 4. Heuristics without AI (all doable from Apps Script)

- Authentication-Results: SPF/DKIM/DMARC (evidence, not verdict).
- Display name vs sender domain; Reply-To and Return-Path mismatches; internal
  vs external (org domain from `Session.getActiveUser()`).
- Lookalike domains: punycode, confusables, edit distance vs org and top brands;
  domain age via RDAP (rdap.org, keyless, ~1 req/s). https://about.rdap.org/
- Links: anchor text vs href host, shorteners, IP literals, deep subdomains.
- Bulk-mail cues: List-Unsubscribe (Gmail mandates one-click since 2024),
  Precedence: bulk, ESP DKIM domains. Strong "newsletter, not phish" signal.
- Content: urgency lexicon, credential/payment/MFA requests, risky attachment
  types, QR images.
- Reputation: Google Web Risk (100k lookups/month free in the customer's GCP
  project; Safe Browsing free tier is non-commercial only); VirusTotal public
  API is prohibited in commercial products; keep VT/urlscan as optional BYO keys.
  https://cloud.google.com/web-risk/pricing
- Google's X-Gm-Spam / X-Gm-Phishy headers only exist with an admin routing
  rule; don't depend on them.

## 5. What makes it a killer app

1. Instant plain-language verdict card: "Looks like a legitimate newsletter
   (DKIM-signed by Mailchimp, one-click unsubscribe)" with "Unsubscribe instead";
   "Internal, sent from your domain"; "Suspicious: 3 red flags".
2. One-click report packet: raw .eml attached, extracted IOCs, heuristic and AI
   summary, user comment, to a security mailbox and Chat/Slack webhook.
3. Admin allowlists of known senders (HR, payroll, IT) that short-circuit reports.
4. Feedback to the user after triage (Defender-style), which Google lacks.
5. Business-tier dashboard (Sheets/Looker Studio): reports and precision per
   user, top spoofed brands.
6. Simulation awareness (KnowBe4/Hoxhunt/GoPhish headers) so tests skip the SOC.
7. Nudges: one-line tip after a false report, thanks after a true one.

Risks: email content to third-party AI (mitigate: Vertex in customer project,
headers-only mode, redaction); 30 s budget means heuristic card first, AI card
second; CASA if restricted scopes in a vendor listing; `cloud-platform` scope
consent; EU customers need paid Gemini tier or EU Vertex region.

## 6. Packaging

Report buttons are commoditised at $0; value is verdict + SOC packet +
dashboard. Suggested: free/open-source heuristics + bring-your-own AI,
customer-deployed (no CASA); Pro ~$1-3/user/yr or flat $2-5k/yr for hosted
dashboard, Chat/Slack integration, managed rules, support.

## Unverified

Labelling via the add-on's message token without gmail.modify; exact IAM role
for user-OAuth Vertex calls; current iOS add-on support; urlscan free quotas;
Hoxhunt/Proofpoint list prices (third-party estimates).
