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

## 2026-09-20 Mail that arrived through a list, group or forwarder
From the third real test. A cold sales email from an external stranger reached
the owner through the `hello@obilabs.dev` Google Group, which rewrites the
visible From to `'Chris Wu' via ObiLabs Hello <hello@obilabs.dev>` and re-signs
the message with the group's own DKIM key. Baitcheck read those headers as the
sender and told the reader **"The sender address is on one of your
organisation's domains (obilabs.dev)"** and **"Signed by obilabs.dev (DKIM
pass)"** — lending a stranger's cold email the organisation's own credibility.
The only line that held up was the Reply-To mismatch, which pointed at a free
`mail.com` address.

This is not a quirk of one mailbox: any organisation with a Google Group, an
alias or a forwarding rule hits it, so relay awareness is a product
requirement, not a workaround. Header-based sender checks are unreliable for
relayed mail, so Baitcheck:
- **detects the relay first** and names it on the card, before any sender-based
  check is shown;
- **evaluates the sender from the original headers** (`X-Original-Sender`,
  `X-Original-From`): internal-domain, lookalike, brand-in-display-name and
  Reply-To alignment all describe the original sender, never the list;
- **never claims an internal sender because of the list.** A message merely
  relayed by one of the organisation's own groups is not internal;
- **never presents a list re-signature as the sender's own.** Where the list
  signed it, the card says the list added that signature, and where
  `X-Original-Authentication-Results` exists it reports the original message's
  SPF/DKIM/DMARC, labelled as the result from before the list handled it;
- **says when it cannot tell.** With no `X-Original-Sender`, the card says the
  headers do not say who sent it rather than falling back to the list.

Detection rule (why this combination, in `detectRelay`): `List-Id` (RFC 2919),
`Mailing-list`, `X-BeenThere`, or Google Groups' `X-Original-Sender` /
`X-Original-From`; plus `Sender:` differing from `From:` plus a `List-Post`
header. `List-Unsubscribe` is deliberately not sufficient, alone or paired with
a differing `Sender` — every competent newsletter carries it and mass-mail
providers set `Sender` to their bounce address, and a newsletter is the sender
of its own mail.

Aliases and forwarders are the weaker neighbouring case and are reported as
weaker. A forward does not rewrite `From`, so the sender checks still hold;
what changes is that forwarding breaks SPF by design (RFC 7208 §11.5.2), so the
card says an SPF failure means less here. `X-Forwarded-To` / `X-Forwarded-For`
name the addresses; a `Delivered-To` that is not on the To or Cc line is stated
as "an alias, a group, a forwarding rule or a Bcc — the headers do not say
which", never asserted.

The report packet keeps schema v1 and **adds** `message.relay` (`via_list`,
`list`, `original_sender`, `original_authentication`, `forwarded`). No existing
field is repurposed: `message.from` and `message.authentication` still describe
the message as delivered, which for relayed mail is the list, so a receiver
must read `relay.via_list` before treating `from` as the sender. The report
email's FACTS section shows the list, the original sender and both sets of
authentication results separately, and its suggested blocks name the original
sender's address and domain — blocking the From address would have blocked the
organisation's own group.

## 2026-09-21 Writes as a company, sends from a personal mailbox
From the fourth real test. A cold sales email reached the founder signed
"Chris Wu · Founder, Anvol" with the company's website under it, and was sent
from `carebearvao@mail.com`. Baitcheck said only **"Sent from a personal email
service (mail.com)"**, filed under *Context* — true, and an under-reading. The
claim and the account are the finding: a sender asserting a company role from a
mailbox anyone can sign up for is exactly the shape of business email
compromise, and exactly the shape of a sole trader who never bought a domain.

So it becomes a finding, worded so both readings survive, and it fires **only on
the combination**:
1. the sender is on a consumer mail provider (`CONSUMER_MAIL_DOMAINS`), **and**
2. the display name asserts an organisation (`organisationClaimInName`): a role
   word (Founder, CEO, CTO, COO, President, Director, VP, Head of, Manager,
   Account Executive, Sales, Support, Billing), a company suffix (Inc, Ltd, LLC,
   Corp, GmbH, Pty, B.V.), or the "person at company" shape (`at`, `|`, `·`).
A body link to a domain that is not the sender's — and not a shortener, bare IP
or click tracker — is reported as corroboration when present, reusing the links
the add-on already extracted; it is never a trigger on its own.

Both halves are named in the text so the reader can judge, and the card says
what settles it: ask them to reply from the company domain. No verdict, no score.

It does not fire when the sender is on one of the organisation's own domains,
or when a relay's original sender is on a company domain — the 2026-09-20 relay
work already resolves the sender to the original, so this check inherits it and
does not re-detect anything.

The provider list is a short, defensible heuristic, not a directory: it will
miss regional providers (Naver, QQ, Mail.ru, Seznam and others), and a sender it
does not match has not thereby been shown to be on a company domain. Zoho is
deliberately excluded: `zoho.com` addresses are not reliably the free tier and
nothing in the headers separates them from paying business users.

Honest false positive, accepted: the sole trader, the consultant and the
one-person agency who legitimately sign "Founder, X" from Gmail will all be
flagged. That is why the wording leads with the gap rather than a verdict and
names the innocent reading in the same breath — and why the real-mail review
(`V1-TODO.md`) must now include at least one legitimate small business sending
from a consumer account, so the rate is measured rather than assumed.

## 2026-09-21 The packet carries the checks, the headers they rest on, and the prompt
A receiver — a dashboard or a person — should be able to see what the add-on
concluded, on what evidence, and exactly what would be asked of an AI. Three
additions, schema still v1, nothing repurposed; a receiver that ignores the new
keys behaves as before.

- **`analysis`**: the heuristic result as data, not only the prose in
  `verdict.reasons`. Each finding is `{id, text, evidence}` using the signal ids
  that already exist in `Heuristics.gs`, with the evidence that check matched on
  (the domain, the header value, the link host, the matched phrases).
  `checks_clear` lists the ids of checks that **ran and found nothing**, and an
  id in neither list **was not run** — no `Authentication-Results` header means
  `dmarc_fail` is absent, not clear. That distinction is the reason the list
  exists: it is what lets the card and the report say what Baitcheck did not
  look at, and it stops a receiver reading silence as reassurance. `evidence`
  never carries body text.
- **`headers`**: a short fixed set — From (name and address apart), Reply-To,
  Return-Path, Sender, Date, Message-ID, List-Id / X-BeenThere /
  X-Original-Sender where present, Delivered-To, Authentication-Results,
  X-Original-Authentication-Results, and the List-Unsubscribe presence flag.
  Not every header, for two reasons: a full dump is several times the size of
  the rest of the packet on every report, and headers carry personal data about
  people who never reported anything (Received hops and internal routing, other
  recipients on To/Cc/Bcc, scanner headers). A team that wants all of it has the
  complete original in the attached `.eml`, which stays the source of truth.
  A header the message did not carry is **omitted, not null**: absence is the
  fact. `has_list_unsubscribe` is presence only, because the value is an
  unsubscribe address that identifies the recipient.
- **`verdict.ai`** gains `sent`, `prompt_template_version`, `prompt`,
  `prompt_includes_message_body` and `note`. With AI off — the default — the
  prompt is still included, marked *"Not sent. AI is off, so this prompt was not
  sent to any provider and none of it left the mailbox…"*. This is a privacy
  feature, not a debug field: "nothing leaves the mailbox" is easy to assert and
  hard to verify, and an administrator can now read the exact words that would
  leave it, on their own real mail, before turning AI on.

The prompt has **one home**, `apps-script/AiPrompt.gs`. The packet publishes
what `buildAiPrompt` returns and any AI call must send what `buildAiPrompt`
returns; a test asserts the two are byte-identical, so a prompt written for the
packet can never drift from the one actually sent. It is versioned
(`baitcheck-triage-1`) because receivers will compare prompts across reports,
and it is capped at 6000 characters. It carries header facts, the check ids and
their text, and the link hosts — **not the message body**; the subject is the
one piece of message content in it, and `prompt_includes_message_body` states
the rule rather than leaving it to be inferred.

Unchanged by this: no verdict and no score, the AI answer stays a labelled
opinion with the provider disclosed (D-042), the evidence card never waits for
AI (Apps Script callbacks cap at 30 s), no new OAuth scopes, and nothing leaves
the mailbox when a message is opened. The only new header read is `Message-ID`,
from the already-loaded message, so opening a message costs no extra request.

## 2026-09-21 The card opens with one headline, one next step and three reasons
The card led with a count ("2 things worth a closer look"), then every finding
as a full sentence, then relay notes and context, with the Report button at
the bottom. People read the first line or two, and a banner that looks the same
every time becomes wallpaper (see `docs/RESEARCH-UX.md`). The quick view
answers the question the reader actually has, "may I
do what this email wants?", in the first few lines.

**Seven fixed headlines, in precedence order.** `link` (links don't go where
they say) > `attachment` > `sender` (the address doesn't match the name) >
`company_claim` > `ask` (asks for money, a sign-in or details) > `bulk` >
`unclear` ("Your call: did you expect this?"). Each names what does not line up,
or what the message asks for, which the message itself proves; none says what
the message *is*, so the verdict ban holds. Each has a fixed next step that
costs a genuine sender nothing (type the address yourself, confirm on a number
you already have, ask them to reply from the company's own address), which is
what lets the card recommend an action without a verdict. The strings live in
one table, `SUMMARY_HEADLINES` in `Heuristics.gs`; the card, the packet
(`analysis.summary`) and the report email all read them from `summarise`.

**No all-clear.** "Nothing stood out" is never the headline: it is a statement
about our checks that reads as one about the message, the green tick in other
clothes. `unclear` replaces it with the question only the reader can answer.
No colour, green or red, carries meaning; the words do.

Choices made while implementing, where the design left room:
- `unclear` is also the headline when the only findings are minor (pressure
  wording, a shortened link, an SPF failure explained by forwarding), so its
  next step is "Nothing here settles it. These checks miss things." rather than
  "found nothing to point at", which would be false with a reason under it.
- A URL shortener is a reason, never a headline: it hides the destination
  rather than showing a mismatch, and "links don't go where they say" is not
  provable from it. (The design allowed it as a headline alongside another
  finding; the simpler rule was taken.)
- No icons. The design made them optional and cosmetic, and an invalid Material
  icon name renders nothing.
- The summary is computed once, in `analyzeFacts`, so every consumer sees the
  same one.

**Gaps closed with it.**
- *The company claim also reads the signature.* The display-name check missed
  the common cold-pitch shape: a plain name on the From line and "Founder" only
  under the message. `organisationClaimInSignature` cuts quoted text first (so a
  reply never inherits the previous writer's signature), drops a mailing-list
  footer, and reads the last eight lines one at a time, never the body as a
  whole. A line only counts when it looks like a signature line: at most eight
  words and 60 characters, not a sentence, no first- or second-person words
  ("Sent from my iPhone", "A note from our CEO", "ask your manager"), and
  "sales", "support" and "billing" do not count there. The same combination
  rule applies (consumer provider AND claim), with the same two-sided wording;
  `evidence.claim_source` (`display_name` or `signature`) lets the
  false-positive rate of the new path be measured on its own. Accepted false
  positives: a real employee writing from personal mail with a work signature,
  and a bare title line in an unquoted forward.
- *Asks are split from pressure.* `payment_or_credential_ask` (bank details,
  wire transfer, gift card, verify your account, reset your password, a
  verification code…) can lead the card; `pressure_language` (urgent, within
  24 hours, final notice…) is a reason only. Both ignore quoted text, or a reply
  to a phish would fire forever. Under `ask`, mail from a passing domain always
  adds "A taken-over mailbox passes those checks too."
- *A group's List-Unsubscribe is not bulk.* Google Groups adds the header to
  everything it relays, so `bulk` requires that the message did not come
  through a list.
- *Relayed mail always says so.* One reason line is reserved under every
  headline ("Came via your <group> group from an outside address", or that the
  headers do not say who sent it), so an outside sender never looks internal.

Packet schema stays v1: `analysis.summary` is additive, signals gain
`category` and `short` in the add-on only (findings keep `{id, text,
evidence}`), and two evidence fields are added (`claim_source`, `where`).

Unverified until a real install: whether the note's `TextInput` inside a
collapsed section is submitted with the Report action. If it is not, the input
moves above the buttons.

## 2026-09-21 Card styling: icons and colour as reinforcement, never green
The quick-view card rendered as plain text and read as unstyled. This reverses
two choices in the previous entry ("No icons"; no colour at all) on the
owner's call, under a narrower rule: **colour and icons only reinforce the
words, and nothing is green.** Every headline still reads the same with both
removed; a test asserts the headline's words are on the card as plain text.

What CardService offers, and what was used (all from
developers.google.com/apps-script/reference/card-service and the
google.apps.card.v1 reference):
- *Icons.* `DecoratedText.setStartIcon` with `IconImage.setMaterialIcon`.
  `MaterialIcon.setName` takes a Google Font icon name, and an invalid name
  "renders nothing", so every name is checked against Google's published
  Material Symbols and Material Icons lists and pinned in
  `test/card-style.test.js`. There is no icon colour setting; `setFill` is
  the only variation, so caution headlines get a filled icon, a cue that does
  not depend on colour. Icons: `link_off` (links), `attach_file` (attachment),
  `alternate_email` (sender), `badge` (company claim), `payments` (ask),
  `campaign` (bulk), `help` (your call); `arrow_right` marks each reason and
  `send` the reported card.
- *Colour.* Text accepts `<font color="#hex">`; nothing else takes colour
  except a filled button's background. The hex is fixed across Gmail's light
  and dark themes, and no fixed colour reaches 4.5:1 on both white and Gmail's
  dark grey (the best possible is about 4:1). So colour goes on the short bold
  headline only: `#d9541e` (warm amber-red) for the five caution headlines,
  `#7a7a7a` (grey) for bulk and "your call", each about 4:1 on white and on
  `#202124`. The next step, reasons and privacy line keep the theme's own
  colour. Tests check the contrast floor and that no colour on the card falls
  in the green hue range.
- *Report button.* Filled, brand teal `#0f6b63`; the reference says a set
  colour makes Gmail pick a contrasting label colour (white on this teal is
  about 6.4:1). It sits in the card's `FixedFooter`, which takes a FILLED
  primary and an OUTLINED secondary, so it stays in view however long the
  card gets; Check links is the secondary. With no report address there is no
  primary, so no footer, and Check links stays inline. The teal is the brand,
  not a status: at about 174 degrees it is outside the green range the test
  forbids, and it is only ever on the action button.
- *Reasons* are one `DecoratedText` row each instead of a bulleted paragraph,
  so their text lines up under the headline's.
- *The note* was copied as "Note for your security team (optional)" three
  times. The code set only the title, once. `TextInput.setTitle` is required
  and Gmail draws it as the field's label and again in the field outline, so
  the repeats are Gmail's rendering (an inference from the copied text; not
  documented). The title is now "Note (optional)", the section header says
  who it is for, and no hint is set, which would add another copy.
- Not used: `CardHeader` image (Gmail already shows the logo and name above
  the card) and `Grid`/`Columns` (nothing on the card is tabular).

Unverified until a real install: how the icons, colours and fixed footer look
in Gmail light and dark themes, on web and on mobile, and whether Gmail
adjusts `<font color>` in dark mode.
