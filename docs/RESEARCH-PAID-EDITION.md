# Paid edition research (2026-09-13)

Question: should Baitcheck have a paid edition, what would make it the
product people reach for first in its category, and why would an organisation
pay instead of asking an AI assistant to write its own Apps Script?

Builds on [`RESEARCH.md`](RESEARCH.md) and [`DECISIONS.md`](DECISIONS.md).
Claims marked **(unverified)** could not be confirmed from a primary source
while writing. Third-party price figures are estimates, not list prices,
unless stated.

## Summary

- **Do not charge for the add-on.** Report buttons are free everywhere
  (KnowBe4, Proofpoint, CanIPhish), the code is Apache 2.0 so any licence gate
  can be deleted by a fork, and Marketplace policy forbids charging to install.
- **Charge for what a script cannot do by itself:** a hosted triage queue with
  feedback to the reporter, report-rate metrics usable as audit or insurance
  evidence, maintained detection content, and support. This matches the
  existing decision that the dashboard is the paid piece.
- **A public Marketplace listing is cheaper than assumed.** All current scopes
  are sensitive or unclassified, not restricted, so a listing needs OAuth
  verification (no fee) but no CASA assessment. The "customer-deployed only"
  decision is worth revisiting for a *free* listing.
- **No Gemini-without-billing API exists for add-ons.** The only zero-billing
  route to Workspace Gemini is Workspace Studio flows, which are asynchronous
  and whose add-on extension point is in limited preview.
- **Heuristics cannot be perfect.** They can be understandable and can cut
  false alarms substantially if the card leads with benign context (bulk mail,
  internal and authenticated, admin-known vendor) rather than a list of flags.

## 1. Gemini inside Workspace without an API key or extra cost

| Path | Uses Workspace Gemini entitlement? | GCP billing? | Fits Baitcheck? |
|---|---|---|---|
| Apps Script Vertex AI advanced service | No | Yes | Yes, synchronous, in the card |
| Gemini API key (AI Studio) via UrlFetch | No | Free tier possible, paid for DPA | Yes, BYO key |
| Workspace Studio "Ask Gemini" step | Yes | No | Asynchronous only; add-on steps in limited preview |
| Gemini side panel in Gmail | Yes | No | Manual, user-driven, no API |

- **Vertex AI advanced service** launched January 2026. It needs a standard
  Google Cloud project with billing, an OAuth consent screen, the
  `cloud-platform` scope and IAM permission; service accounts are not
  supported; preview models are not available.
  https://developers.google.com/apps-script/advanced/vertex-ai ,
  https://pulse.appsscript.info/p/2026/01/vertex-ai-advanced-service-in-apps-script-a-step-forward-or-a-missed-opportunity/ ,
  https://pulse.appsscript.info/p/2026/03/q1-2026-developer-roundup-vertex-ai-agentic-add-ons-and-the-growth-of-workspace-studio/
- No built-in (`LanguageApp`-style) Gemini service for Apps Script was found,
  and no API lets an add-on draw on a user's Workspace Gemini licence.
- **Workspace Studio** (formerly Flows) became available to Rapid and
  Scheduled Release domains on 2026-03-19. It has an "Ask Gemini" step, needs
  no Cloud project, and runs on the Workspace entitlement with per-user usage
  limits after 2026-06-01. Add-ons can contribute custom steps, but that is in
  limited preview. New Gmail steps roll out from 2026-09-14 on Business,
  Enterprise and Education editions.
  https://developers.google.com/workspace/add-ons/studio ,
  https://workspaceupdates.googleblog.com/2026/09/automate-drive-gmail-and-google-chat-actions-with-new-steps-in-Workspace-Studio.html ,
  https://support.google.com/workspace-studio/answer/16433731
  Whether a flow can trigger on every received message and pass Gemini's
  output into an add-on step is **(unverified)**.
- **Data terms:** Workspace's generative AI privacy commitments cover Google's
  own Gemini features. Third-party apps are governed by their own terms, so an
  add-on's AI calls must cite Cloud (Vertex) or Gemini API terms instead.
  https://knowledge.workspace.google.com/admin/generative-ai/generative-ai-in-google-workspace-privacy-hub

**Cheapest real path.** Customer-deployed: enable Vertex in the customer's own
project (billing on, grant an IAM role such as Vertex AI User to a group,
add the advanced service), cost around a fraction of a cent per analysis on a
Flash model. Vendor-listed add-on: the script runs in the vendor's project, so
AI must be the customer's key (AI Studio or other provider) or a call into the
customer's project with the user's token **(unverified: IAM and consent
behaviour across projects)**. A Workspace Studio template ("when a message is
reported, ask Gemini, post to the security space") is the only zero-billing
option and is worth watching, not building on, until add-on steps leave
preview.

## 2. Overlap with Gemini in Gmail

- Since the January 2025 repricing, Gemini in the Gmail side panel is included
  in all Business plans, including Starter.
  https://9to5google.com/2025/01/15/google-workspace-gemini-price-increase/
- The side panel can summarise and answer questions about the open email, so a
  user can type "is this phishing?".
  https://support.google.com/mail/answer/14199860
  No published evaluation of its phishing answers was found. Whether it sees
  full headers (Authentication-Results, Reply-To) rather than rendered content
  is **(unverified)**; its help pages describe it as working on email content.
- It has been manipulated through hidden text in emails (indirect prompt
  injection producing fake security alerts in summaries). Google describes
  layered defences.
  https://www.bleepingcomputer.com/news/security/google-gemini-flaw-hijacks-email-summaries-for-phishing/ ,
  https://support.google.com/mail/answer/16204578
- General LLM evidence: frontier models' false-positive rates degrade under
  adversarial and non-English inputs, and accuracy and explanation consistency
  do not always go together.
  https://arxiv.org/html/2512.10104v2 , https://arxiv.org/abs/2506.13746

**What it does not do for a security team:** no report, no raw .eml, no
structured packet, no consistent wording between users, no record, no metrics,
no admin policy. Native "User reports" in the admin console exists only on
Enterprise Plus, Education Standard/Plus, Frontline Plus and Enterprise
Essentials Plus.
https://knowledge.workspace.google.com/admin/security/user-report

**Implication:** Baitcheck should not compete on "an opinion about this email".
Gemini will give that for free and improve. Baitcheck's value is the
consistent, explainable evidence card, the one-click packet, and what happens
after the report.

## 3. Marketplace reality

**Scope classification** (Gmail API scopes page):

| Scope | Class |
|---|---|
| `gmail.addons.execute` | Not listed as sensitive or restricted |
| `gmail.addons.current.message.readonly` | Sensitive |
| `gmail.send` | Sensitive |
| `script.external_request` | Not listed as sensitive or restricted |
| `gmail.modify`, `gmail.readonly`, `gmail.metadata` | Restricted |

https://developers.google.com/workspace/gmail/api/auth/scopes ,
https://developers.google.com/workspace/add-ons/concepts/workspace-scopes

- **Sensitive scopes:** app verification only (privacy policy on a verified
  domain, unlisted YouTube demo video, per-scope justification); typically
  3-5 business days; no annual cycle; no fee found in Google's documentation.
  https://developers.google.com/identity/protocols/oauth2/production-readiness/sensitive-scope-verification
- **Restricted scopes:** verification plus a CASA assessment by an empanelled
  assessor, at least every 12 months, when restricted data can reach a
  third-party server. Tier 2 self-scan is no longer an option; lab prices seen
  range roughly USD 540 to 1,500+ per assessment.
  https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification ,
  https://www.switchlabs.dev/post/casa-tier-2-tier-3-security-review-providers-pricing-and-the-cheapest-option ,
  https://deepstrike.io/blog/google-casa-security-assessment-2025
- **Consequence:** with today's scopes a public listing needs verification but
  not CASA, even if a connected mode sends message content to a hosted
  dashboard (that data comes from a sensitive, not restricted, scope). Any
  "known sender history" feature built on `gmail.readonly` would pull in CASA.
- **No verification needed:** internal apps (consent screen set to Internal,
  used only inside the owning organisation), personal/testing use under 100
  users (with warning), and apps an admin marks as trusted.
  https://support.google.com/cloud/answer/13464323
- **Billing:** Google does not process payments for Marketplace apps. The
  listing can be labelled Free, Paid, Paid with free trial, or Paid with free
  features; the developer is the seller and collects payment itself. Charging
  to install is not allowed; licensing features after install is common.
  https://developers.google.com/workspace/marketplace/terms/policies ,
  https://developers.googleblog.com/en/app-pricing-update-details-and-editors-choice-now-available-on-google-workspace-marketplace/
  A Marketplace billing API existed in 2010
  (https://gsuite-developers.googleblog.com/2010/09/google-apps-marketplace-billing-api-and.html);
  the retirement date is **(unverified)**. The Marketplace API still exposes
  install/licence status, not payments.
  https://developers.google.com/workspace/marketplace/reference/rest
- **What vendors do instead:** Stripe (or similar) checkout plus a licence
  record keyed on the Google user or domain, checked from the add-on against
  the vendor's own endpoint. https://mailmeteor.com/blog/monetize-google-workspace-addon
  This means a "paid Marketplace app with no vendor servers" is not really
  possible: at minimum a licence endpoint and a webhook receiver are needed.
- **Private distribution without a public listing:** publish through the
  Marketplace SDK with visibility Private (installable only in the owning
  domain), or have the customer deploy the script in its own project. Neither
  lets one vendor listing serve many customers privately.

## 4. Can heuristics without AI be "perfect, relevant and understandable"?

Not perfect. They can be relevant and understandable.

- **Base rate:** in Hoxhunt's network (5M users, April 2025 to April 2026),
  80-85% of user-reported emails were benign; 15-20% malicious.
  https://hoxhunt.com/blog/user-reported-phishing-response-automation
  Any rule that fires on "external + link + urgency" will fire on most
  legitimate vendor mail.
- **Warnings wear out.** Banners on most messages habituate users within
  weeks; false positives erode trust in the warning itself. Placing warnings
  at the point of action and explaining the reason improves outcomes.
  https://dl.acm.org/doi/fullHtml/10.1145/3290605.3300748 ,
  https://dl.acm.org/doi/fullHtml/10.1145/3544549.3585802 ,
  https://hoxhunt.com/blog/external-email-warning-banner-phish
- **Signals that most reduce false alarms (all available with current scopes):**
  1. Bulk/marketing mail: `List-Unsubscribe` with one-click, aligned DKIM from
     the sending domain. Gmail requires one-click unsubscribe for marketing
     mail from senders above 5,000 messages/day and has enforced it more
     strictly since November 2025.
     https://support.google.com/a/answer/81126 , https://support.google.com/a/answer/14229414
  2. Internal and authenticated: sender on `ORG_DOMAINS` with DMARC pass.
     Caveat: compromised internal accounts pass this.
  3. Admin-known senders: an allowlist of payroll, HR, LMS, SIS and finance
     vendors, shown as "Known vendor set by your IT team".
  4. Simulation headers from training vendors, so tests are recognised
     instead of queued.
  Known-sender *history* (have I emailed them before?) needs `gmail.readonly`,
  a restricted scope; the admin allowlist is the practical substitute.
- **Explaining verdicts:** commercial tools pair a short verdict with a few
  reasons and a recommended action; Microsoft sends the reporter a result
  after triage. Plain-language patterns that test well: lead with one sentence
  ("This looks like a newsletter from Mailchimp"), show at most three reasons,
  offer the safer alternative ("Unsubscribe instead"), and say what is not
  known ("Baitcheck cannot see where this link redirects").
- **Honest limit:** well-crafted business email compromise from a real or
  lookalike account with no links often trips nothing. The card should say
  "nothing unusual found", never "safe".

## 5. What people pay for, and what DIY cannot easily provide

| Product | Model | Price (USD) | Source |
|---|---|---|---|
| KnowBe4 PhishER Plus | Triage platform | List $1.50/seat/month (101-500), $1.15 (501-1,000), 101-seat minimum | https://www.knowbe4.com/products/phisher-plus/pricing |
| Hoxhunt | Training + reporting + instant feedback | ~$12-18/user/yr at 500-1,500 users, from ~$10k/yr (estimate) | https://www.vendr.com/marketplace/hoxhunt |
| IRONSCALES | Email security + reporting | from ~$3.49/mailbox/month, mid-market $4-9 (estimate) | https://expertinsights.com/email-security/ironscales-review |
| Abnormal | Behavioural email security | ~$20-35/mailbox/yr plus platform fee (estimate) | https://underdefense.com/blog/abnormal-security-pricing-guide/ |
| Sublime Security | Open rules (MIT) + platform; free Core up to 100 mailboxes; paid Enterprise | quote | https://github.com/sublime-security/sublime-rules , https://sublime.security/plans/ |
| Proofpoint Report Suspicious, CanIPhish, KnowBe4 PAB | Report button | Free with their platforms | Marketplace listings, https://help.caniphish.com/hc/en-us/articles/4708297346063-Google-Workspace-Phish-Report-Add-on |
| Material Security | Workspace security | quote, not found | |

**Sublime is the closest model:** detection rules are open and
community-contributed (over a third of the default catalogue), the engine is
free for small tenants, and money comes from scale, automation and operations.

**What an AI-written script does not give an organisation:**

1. Domain-wide install and silent updates across every user (an admin
   deployment, versioned, with rollback).
2. Detection content that someone keeps current (brand domains, lookalikes,
   ESP and simulation headers) and tests against a regression set.
3. A triage queue: dedupe identical reports, mark outcome, notify the reporter.
4. Metrics over time: report rate, time to triage, share benign, repeat
   reporters. This is evidence, not detection.
5. A published scope and data-flow review, a security contact, and someone
   accountable when it breaks.
6. Training-vendor awareness so simulations don't flood the security inbox.

A DIY script can do the first card in an afternoon. The rest is ongoing work,
which is what buyers pay for.

**Compliance and insurance pressure (a reporting mechanism and evidence):**

- CIS Controls v8.1 safeguard 14.6 (IG1): train workforce to recognise and
  report potential incidents. https://cas.docs.cisecurity.org/en/latest/source/Controls14/
- Canadian Centre for Cyber Security baseline controls for small and medium
  organisations include security awareness training and incident response
  planning. https://www.cyber.gc.ca/en/guidance/baseline-cyber-security-controls-small-and-medium-organizations
- K-12: the CIS MS-ISAC 2025 K-12 report and CISA's K-12 guidance stress
  phishing resistance and fast response to user reports.
  https://www.cisecurity.org/insights/white-papers/2025-k12-cybersecurity-report ,
  https://www.cisa.gov/K12Cybersecurity
- Cyber insurance supplemental applications commonly ask about awareness
  training and phishing simulation results; that carriers specifically require
  a *report button* or report-rate metrics is **(unverified)**.
  https://www.adaptivesecurity.com/blog/cybersecurity-awareness-training-cyber-insurance
  Report rate is increasingly used as the positive counterpart to click rate,
  which makes a reporting tool's metrics useful evidence even where not named.

## 6. Recommendation

### (a) Whether to charge, and for what

| Item | Charge? | Why |
|---|---|---|
| Add-on (script and any Marketplace listing) | No | Free everywhere; Apache code; install charges not allowed |
| Heuristics and detection content (brand lists, rules) | No | Open content builds trust and contributions (Sublime model) |
| Self-hosted triage (Google Sheet receiver) | No | Keeps "works without paying" true |
| Hosted triage queue + reporter feedback + metrics reports | Yes | Needs operation; directly saves analyst time; audit evidence |
| Managed rollout and support (setup, annual review) | Yes | A service; fits the company's "services are paid" rule |

Price range grounded in comparables, per organisation per year: roughly
**$1-3 per user**, or flat tiers that suit school and nonprofit budgets
(for example a small tier under 250 users, a mid tier to 1,000, quote above),
with education and nonprofit discounts. That sits well below PhishER Plus
($13.80-18/user/yr, 101-seat minimum) and Hoxhunt, which bundle more.

### (b) Five features, ranked by value for effort

1. **Benign-first card:** newsletter, internal-authenticated, admin-known
   vendor, and training-simulation recognition, shown before any red flag.
   Targets the 80-85% benign share. Low effort.
2. **Reporter feedback loop:** the security team marks a packet outcome and
   the reporter gets a short thank-you with the result. Google offers nothing
   equivalent below Enterprise Plus. Medium effort; free Sheet version first.
3. **Maintained open detection content:** versioned brand, lookalike, ESP and
   simulation-header lists fetched from a static file, updated without
   redeploying. Low effort, ongoing.
4. **Evidence report:** monthly report rate, share benign, time to triage, as
   a CSV or PDF suitable for an audit or insurance renewal. Low-medium effort
   once the queue exists.
5. **One-click domain install:** a free public Marketplace listing (sensitive
   scopes only, verification, no CASA) with optional BYO-key AI. Medium effort,
   mostly paperwork.

### (c) Staying free and open

Must stay free: the add-on, every heuristic, the report packet schema, the
detection content, a self-hosted receiver, and the privacy default that
nothing leaves the mailbox on open. Paid is only operation (hosting, updates
on a schedule, support), never a feature locked inside the add-on.

### (d) Risks

- **Google builds it:** Gemini in Gmail or native user-report feedback could
  cover the card. Mitigation: value lives in the packet, queue and evidence,
  which are vendor- and mailbox-neutral.
- **CASA creep:** adding `gmail.modify` (trash, label) or `gmail.readonly`
  (sender history) to a public listing triggers annual assessment. Keep scopes
  sensitive-only.
- **Support burden:** every domain install creates questions. Keep the free
  tier self-serve with documentation; support only for paying organisations.
- **Hosted data:** a hosted queue holds reported messages, which raises data
  residency (Canada, EU) and breach responsibility. Offer self-hosting.
- **Licence enforcement:** an open-source add-on cannot enforce a licence;
  paid value must sit server-side.
- **AI data terms:** free-tier AI Studio keys have weaker data terms than paid
  Vertex or Gemini API; say so in settings.

### Conflicts with existing decisions

1. **"Paid Marketplace app, no vendor servers"** (the proposal) conflicts with
   the decision that the add-on is free, with the Apache licence (a gate can be
   forked out), and with how Marketplace billing works (payments and licence
   checks need a vendor endpoint). This research recommends against it.
2. **"Customer-deployed internal add-on, not a Marketplace listing"**
   (2026-09-03) assumed verification and CASA cost. With current scopes, CASA
   does not apply; a free public listing is worth reconsidering. The
   customer-deployed route stays best for customers who want Vertex in their
   own project.
3. **"Products are free except MTP and services":** a hosted triage and
   metrics service plus support can be framed as a service. A paid add-on
   edition could not, and would need an explicit exception.
