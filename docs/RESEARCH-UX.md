# UI/UX research brief (2026-09-16)

Scope: the card a person sees when they open a message, and the reporting flow.
Constrained by `docs/DECISIONS.md` and north-star D-040 to D-042: free add-on and free
Marketplace listing, the paid product is the hosted triage service, AI is optional with
an organisation-supplied key and labelled an opinion, nothing leaves the mailbox on
open, sensitive scopes only, non-punitive framing. Every claim below carries a link or
a file reference; inferences are labelled.

## 1. What the platform allows

- **Widgets:** card, header, section, button set, fixed footer, peek card;
  `TextParagraph`, `DecoratedText`, `Image`; `TextButton`, `ImageButton`, `TextInput`,
  `SelectionInput`, `Switch`, `Grid`, pickers. Text allows only `<b> <i> <u> <s>
  <font color> <a href> <time> <br>`; labels are plain text
  ([widgets](https://developers.google.com/workspace/add-ons/concepts/widgets)). There
  is no spinner or progress widget.
- **Limits:** "A card can have no more than 100 card sections" and "A card section can
  have no more than 100 widgets"
  ([cards](https://developers.google.com/workspace/add-ons/concepts/cards)); sections
  collapse with the first *n* widgets kept visible
  ([CardSection](https://developers.google.com/apps-script/reference/card-service/card-section)).
- **Width:** undocumented. Google says only that add-ons appear in "the sidebar of the
  host application UI"
  ([card interfaces](https://developers.google.com/workspace/add-ons/concepts/card-interfaces));
  the only published widths are the `Columns` wrap points (web 480 px, iOS 300 pt,
  Android 320 dp,
  [card v1](https://developers.google.com/workspace/add-ons/reference/rpc/google.apps.card.v1)).
  *Inference:* design for a narrow column — one short sentence per line, no tables, no
  two-column layouts, long domains truncated.
- **Triggers:** a homepage trigger with no message open; an unconditional contextual
  trigger on open, handing over a per-message token
  ([message UI](https://developers.google.com/workspace/add-ons/gmail/extending-message-ui)).
  Both are already wired in `apps-script/appsscript.json`.
- **Latency:** "The Apps Script Card service limits callback functions to a maximum of
  30 seconds of execution time. If the execution takes longer than that, your add-on UI
  might not update its card display properly"
  ([actions](https://developers.google.com/workspace/add-ons/concepts/actions)). With no
  spinner, a slow action just looks broken — the technical reason the evidence card must
  never wait for AI (D-042), not only a policy one.
- **Mobile:** in the Gmail apps the icons "appear as a horizontal row at the bottom of
  the open message or draft" and open the interface there
  ([using add-ons](https://developers.google.com/workspace/add-ons/guides/using-addons)).
  The card is a bottom sheet the user opens deliberately, so the first two or three
  widgets are all most people see.
- **Style rules that bind us:** sentence case; verb-first button labels; "Button rows
  should be limited to three or fewer buttons in most cases"; no "Google" or "Gmail" in
  the name or branding text
  ([style guide](https://developers.google.com/workspace/add-ons/guides/workspace-style));
  errors belong in a card with a corrective step
  ([best practices](https://developers.google.com/workspace/add-ons/guides/workspace-best-practices)).
- **Listing:** OAuth verification covers our sensitive scopes; only restricted scopes
  trigger the annual assessment. Needs icon, screenshots, two distinct descriptions,
  privacy policy, EEA trader status; review "typically takes several days"
  ([app review](https://developers.google.com/workspace/marketplace/about-app-review)).
- **Limited Use** constrains the AI feature: transfers are allowed only to provide the
  feature and "only with the user's consent", and data may not be used "to create,
  train, or improve a machine learning or artificial intelligence model"
  ([policy](https://developers.google.com/workspace/workspace-api-user-data-developer-policy)).
  A free-tier key that trains on submitted content is incompatible with a public listing.

## 2. How comparable tools present this

- **Microsoft's built-in Report button:** a split button (Report phishing / junk / not
  junk). Admins can enable a confirmation pop-up ("Ask the user to confirm before
  reporting") and a success pop-up, customisable in up to seven languages. Junk moves to
  the Junk folder; "Reported as phishing: The messages are deleted." An admin verdict
  later returns to the reporter by email
  ([report messages](https://learn.microsoft.com/en-us/defender-office-365/submissions-outlook-report-messages),
  [settings](https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox)).
  The older add-ins are "now in maintenance mode and will eventually be deprecated"
  ([transition](https://learn.microsoft.com/en-us/defender-office-365/submissions-users-report-message-add-in-configure)).
- **KnowBe4's Phish Alert Button:** one button, a confirm pop-up with Report and cancel,
  and the mail leaves the inbox — KnowBe4's guide says it "will be deleted from your
  inbox"; university pages say Deleted Items. On Outlook mobile it hides under the
  three-dot menu. Simulations can return gamification and a leaderboard
  ([PAB guide](https://support.knowbe4.com/hc/en-us/articles/219122288-Phish-Alert-Button-PAB-in-Microsoft-Outlook-Guide),
  [gamification](https://support.knowbe4.com/hc/en-us/articles/53283624795667-Phish-Alert-Button-PAB-Gamification-Overview),
  [Memphis ITS](https://www.memphis.edu/its/security/phish-alert-button-outlook.php)).
  *Labelled:* KnowBe4 blocks automated fetching, so this comes from search snippets of
  those pages plus a university page, not a direct read.
- **Hoxhunt:** report as phishing, optionally as spam, plus an "Already clicked
  something?" declaration. Optional Instant Feedback returns "a detailed summary of the
  maliciousness likelihood, potential threat indicators, and tips" inside the flow
  ([Hoxhunt](https://hoxhunt.com/product/automated-phishing-analysis-with-instant-feedback)).
  That is the shape of our paid service — but after the report, where we show evidence
  before it.
- **Gmail itself:** More, then Report phishing, moves the message to Spam and reports it
  to Google ([Gmail Help](https://support.google.com/mail/answer/8253?hl=en)). The
  documented banner is "This message could be a scam", offering report or "Looks safe"
  ([Gmail Help](https://support.google.com/mail/answer/1074268?hl=en)). The widely quoted
  red "This message seems dangerous" string appears only in user-written community
  threads — unverified. Note the disagreement: Google offers a safe verdict; we will not.
- **Open source:** Gophish has no button — users forward to a mailbox it polls over
  IMAP, and the docs suggest rewarding reporters out of band, so the user sees nothing
  in-product ([Gophish](https://docs.getgophish.com/user-guide/documentation/email-reporting)).
  Cofense Reporter's end-user flow is described only by customers (confirmation, message
  to Trash)
  ([Georgetown](https://uis.georgetown.edu/security/reporting-a-suspicious-email-with-cofense-reporter/));
  third-party, not vendor documentation.
- **The pattern, and where we break it.** All of them: one prominent action with two or
  three sub-choices, a confirm step, the message leaving the inbox, an immediate success
  message, delayed feedback. We match all but the third — moving mail needs
  `gmail.modify`, ruled out — so users will assume ours removed the mail and the
  confirmation has to say it did not.

## 3. What the warning research says

- Design, not human nature, decides adherence: Akhawe and Felt measured over 25 million
  impressions and found click-through of about a tenth of Firefox malware/phishing
  warnings, a quarter of Chrome's, but 70.2% of Chrome's SSL warnings
  ([USENIX 2013](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/akhawe)).
- Cranor's human-in-the-loop framework names the failure points: impediments, the
  receiver's "personal variables", "intentions" and "capabilities", then "attention
  switch and attention maintenance", comprehension, application, behaviour
  ([UPSEC 2008](https://www.usenix.org/legacy/event/upsec08/tech/full_papers/cranor/cranor_html/)).
  Our card competes with the message for attention; its job is comprehension plus one
  clear next action.
- Habituation is physical: fMRI showed "a dramatic drop in the visual processing centers
  of the brain after only the second exposure to a warning", and warnings that vary
  resist it ([CHI 2015](https://dl.acm.org/doi/10.1145/2702123.2702322)). A fixed banner
  becomes wallpaper; findings that differ per message do not.
- **The literature pulls against our own decision.** Felt and colleagues report "nearly
  30% more total users chose to remain safe" after an opinionated Chrome SSL redesign,
  while conceding they "failed at their goal of a well-understood warning"
  ([CHI 2015](https://research.google/pubs/pub43265/)). An opinionated Baitcheck would
  likely be obeyed more often. We decline it anyway: the checks in
  `apps-script/Heuristics.gs` are shallow enough that confident verdicts would often be
  wrong, and a wrong confident verdict spends the credibility of the next hundred.
- Placement matters and ours is the weak one: Petelka, Zou and Schaub (n=701) found
  "link-focused phishing warnings reduced phishing click-through rates compared to email
  banner warnings; forced attention warnings were most effective"
  ([CHI 2019](https://dl.acm.org/doi/10.1145/3290605.3300748)). An add-on cannot reach
  into the body, so specificity is the compensation — quote the link text and its real
  destination, as `link_text_mismatch` does.
- Explanations protect good mail: Buono and colleagues (n=300) found explanations
  "resulted useful in preventing users from discarding genuine emails where warnings are
  displayed incorrectly due to misclassification"
  ([CHI EA 2023](https://dl.acm.org/doi/10.1145/3544549.3585802)). That is the strongest
  external support for evidence-first.
- The button itself is the proven part: over 15 months and 14,000+ employees, embedded
  training "does not make employees more resilient to phishing" while a reporting button
  made employees "as a collective phishing detection mechanism" workable
  ([IEEE S&P 2022](https://arxiv.org/abs/2112.07498)).
- Reporting culture: NCSC says "spotting all phishing emails is hard", "Don't reprimand
  users who are struggling to recognise phishing emails", reporting should be "clear,
  simple and quick to use" and "Quickly provide feedback on what action has been taken",
  and measurement should count who reported, not only who clicked
  ([NCSC](https://www.ncsc.gov.uk/guidance/phishing)). That is why report rate is the
  headline metric.
- Disagreements: Anderson treats habituation as the central failure, while Reeder and
  colleagues, surveying 6,000+ users in the field, "did not find a single dominant
  failure in modern warning design"
  ([CHI 2018](https://research.google/pubs/an-experience-sampling-study-of-user-reactions-to-browser-warnings-in-the-field/));
  and CISA holds that training prevents attacks
  ([CISA](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/teach-employees-avoid-phishing))
  where NCSC doubts any package can. Both agree on no-blame, the part that touches this
  design.

## 4. Reporting UX specifically

Before sending: show evidence and the destination, not a score — the person holds the
context we lack ("I did order this"). Naming the security address and saying the message
stays put answers the two questions that stop people reporting. Evidence over verdict,
with the limit stated: the packet already caps itself at `suspicious` or `unknown`
(`apps-script/Report.gs`). The dangerous case is "looks fine": never render a green
state, because absence of findings is a statement about our checks, not the message.
Nothing in the card scores the user, and the hosted service's headline number is report
rate, never a per-person ranking.

## 5. Proposal: the card

Header `Baitcheck` / `Evidence first. You decide.` (as today), then:

1. **Summary** — one `DecoratedText`. With findings: **"3 things worth a closer look"**,
   bottom label "Local checks only. Nothing has left your mailbox." With none:
   **"Nothing stood out in these checks"**, then "These checks are simple and can miss
   things. This is not a statement that the message is safe." (Today's wording instead
   gives advice about links; the replacement is a statement about our own coverage.)
2. **Findings**, strongest first, one short paragraph each, each naming the concrete
   thing: "Replies would go to mail-support.net, not to the sender's domain
   paypal.com." Beyond the first three, a collapsible "More findings" section, so the
   mobile bottom sheet opens on what matters.
3. **Context** (collapsed): internal sender, DKIM signer, List-Unsubscribe, link counts.
   Neutral by construction, never leading, never read as reassurance.
4. **Link reputation** — unchanged: a sentence naming exactly what would be sent and to
   which services, the button, then results or "None of the checked links are on the
   enabled lists. Not being listed does not make a link safe."
5. **Report** — optional note, then the action.

## 6. Proposal: actions and what follows

Two buttons in practice, three at most (style guide).

- **"Report to security"** → `sendReport`. On success the card becomes: "Reported. Your
  security team has the message and will look at it. Baitcheck did not move or delete it
  — delete it yourself if you want it gone. Report ID <id>." The middle sentence is new
  and load-bearing, given every comparable tool removes the mail.
- **On failure**, the existing "Could not send the report. Please forward the message to
  your security team." should name the address, so the fallback is actionable.
- **"Check links"** — unchanged, only when a service is configured.
- **No security address configured.** Today: "Reporting is not set up yet. Ask your
  admin to set REPORT_ADDRESS" — developer language in a user's mailbox. Proposed: "Your
  organisation has not set a reporting address, so Baitcheck cannot send this anywhere.
  Forward the message to your IT or security contact instead." Evidence still renders;
  the add-on stays useful without the report path.

## 7. Proposal: the optional AI opinion

The evidence card renders and returns without AI, always. When configured, a button
**"Ask for a second opinion"** returns an updated card with a section headed "Second
opinion (<provider>)" holding a short paragraph and the label "This is a machine
opinion, not a verdict. It can be wrong. Your security team decides." The button's
supporting line states what leaves the mailbox — "Sends this message's text to
<provider> under your organisation's account" — and pressing it is the consent Limited
Use requires. When AI is off there is no section and no greyed-out button; an absent
feature is quieter than a disabled one on a narrow card. There is no spinner, so the
call needs its own timeout well inside 30 seconds, returning "No second opinion came
back in time. The findings above are unchanged."

## 8. Accessibility, localisation, mobile

Google renders the widgets, so contrast and focus order are Google's. What we control:
never encode meaning in colour alone, keep every finding a full sentence that reads
correctly aloud out of context, alt text on images. `useLocaleFromApp` is already true
in the manifest, but reading `userLocale` needs the `script.locale` scope, which we do
not request
([locale](https://developers.google.com/workspace/add-ons/guides/access-user-locale-timezone))
— add the scope or drop the flag. Copy stays English for now and should be
translation-ready: no idioms, and whole sentence templates instead of today's
concatenated fragments. On mobile the card is a bottom sheet at the end of the message:
the summary and first two findings carry everything, and the note field costs a
keyboard, so it stays last and optional.

## 9. What to measure without tracking anybody

Legitimate, only with the hosted service and an opted-in organisation: reports received
per organisation per day; the distribution of finding IDs across reports; share judged
harmless; time to triage; add-on version and locale. All derivable from the packet.

Not acceptable: anything sent when a message is merely opened (the tests enforce this);
per-user report counts exposed as a ranking; IP addresses (D-052: country code at most);
message content kept beyond triage; any use of message content to train a model.

## 10. What I would not build

- A risk score or traffic light — it invites the false positive that costs trust.
- A "looks safe" or "mark as safe" control — we cannot support the claim.
- Move, label or trash the reported message — needs `gmail.modify` and the annual
  security assessment.
- Blocking or interstitial UI — we cannot block anything, and forcing attention on every
  message is how habituation starts.
- Per-user report statistics in the add-on — a wall of shame in miniature.
- An always-on AI opinion — breaks the latency budget and the consent model at once.

## Open questions

- The rendered panel width is undocumented; measure it on desktop and both mobile apps
  before fixing copy.
- Does "don't include Google product names" reach body text naming services ("Google Web
  Risk")? It is written about names and branding, so `apps-script/Lookups.gs` labels are
  probably fine, but review is the only authority.
- With a public listing, where do per-organisation settings live? Script Properties are
  shared across installing organisations (already flagged in `docs/DECISIONS.md`). Every
  proposal here assumes a per-organisation address and provider exist somehow.
- No API triggers Gmail's own "Report phishing" (`docs/RESEARCH.md`), so reports never
  reach Google's classifier. Tell the user, or noise?
- Should the reporter's address be in the packet? It is `null` today because reading it
  needs another scope, and the report email's sender already identifies them.
- The repo's own `CLAUDE.md` still says "Customer-deployed... No Marketplace listing, no
  CASA" and "shows a plain-language verdict", both superseded by the 2026-09-13
  decisions (D-040, evidence-not-verdict). It needs correcting, in its own change.

## What this changes in the current code

Nothing in this PR. What it implies, by file:

- `apps-script/Ui.gs` — `buildMessageCard` (finding order, collapsible "More findings"
  and "Context", the no-findings sentence, the no-report-address wording);
  `buildReportedCard` (say the message was not moved); `onReport`'s failure message
  (name the address); a new `onSecondOpinion` action and section.
- `apps-script/Heuristics.gs` — `analyzeFacts` emits findings in check order with no
  weight; add a severity and sort. Finding text is string-concatenated throughout, which
  blocks localisation.
- `apps-script/Config.gs` — `parseConfig` gains AI provider/key and a per-organisation
  settings source once the listing question is answered.
- `apps-script/appsscript.json` — add `script.locale` or drop `useLocaleFromApp`; any AI
  host must join `urlFetchWhitelist`.
- `apps-script/Report.gs` — unchanged; `verdict.label` stays `suspicious`/`unknown`.
- `apps-script/test/addon.test.js` — the "no network on open" test must keep passing once
  the AI action exists.

## Sources

Platform

- Widgets: https://developers.google.com/workspace/add-ons/concepts/widgets
- Cards and limits: https://developers.google.com/workspace/add-ons/concepts/cards
- Card interfaces: https://developers.google.com/workspace/add-ons/concepts/card-interfaces
- CardSection: https://developers.google.com/apps-script/reference/card-service/card-section
- Actions, 30-second limit: https://developers.google.com/workspace/add-ons/concepts/actions
- Triggers: https://developers.google.com/workspace/add-ons/concepts/workspace-triggers
- Extend the message UI: https://developers.google.com/workspace/add-ons/gmail/extending-message-ui
- Using add-ons (desktop and mobile placement): https://developers.google.com/workspace/add-ons/guides/using-addons
- Style guide: https://developers.google.com/workspace/add-ons/guides/workspace-style
- Best practices: https://developers.google.com/workspace/add-ons/guides/workspace-best-practices
- Locale and timezone: https://developers.google.com/workspace/add-ons/guides/access-user-locale-timezone
- Card v1 column wrap points: https://developers.google.com/workspace/add-ons/reference/rpc/google.apps.card.v1
- Marketplace app review: https://developers.google.com/workspace/marketplace/about-app-review
- Workspace user data policy (Limited Use): https://developers.google.com/workspace/workspace-api-user-data-developer-policy

Comparable tools

- Microsoft, report messages: https://learn.microsoft.com/en-us/defender-office-365/submissions-outlook-report-messages
- Microsoft, user reported settings: https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox
- Microsoft, add-ins in maintenance mode: https://learn.microsoft.com/en-us/defender-office-365/submissions-users-report-message-add-in-configure
- KnowBe4 PAB in Outlook: https://support.knowbe4.com/hc/en-us/articles/219122288-Phish-Alert-Button-PAB-in-Microsoft-Outlook-Guide
- KnowBe4 PAB gamification: https://support.knowbe4.com/hc/en-us/articles/53283624795667-Phish-Alert-Button-PAB-Gamification-Overview
- University of Memphis on PAB behaviour (third-party): https://www.memphis.edu/its/security/phish-alert-button-outlook.php
- Hoxhunt instant feedback: https://hoxhunt.com/product/automated-phishing-analysis-with-instant-feedback
- Hoxhunt reporting: https://support.hoxhunt.com/hc/en-us/articles/360000981131-Reporting-Suspicious-Emails-Phishing-or-Spam
- Gmail, report phishing: https://support.google.com/mail/answer/8253?hl=en
- Gmail, "This message could be a scam": https://support.google.com/mail/answer/1074268?hl=en
- Gophish email reporting: https://docs.getgophish.com/user-guide/documentation/email-reporting
- Cofense Reporter, customer page (third-party): https://uis.georgetown.edu/security/reporting-a-suspicious-email-with-cofense-reporter/

Research and guidance

- Akhawe and Felt, Alice in Warningland, USENIX Security 2013: https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/akhawe
- Cranor, A Framework for Reasoning about the Human in the Loop, UPSEC 2008: https://www.usenix.org/legacy/event/upsec08/tech/full_papers/cranor/cranor_html/
- Anderson et al., How Polymorphic Warnings Reduce Habituation in the Brain, CHI 2015: https://dl.acm.org/doi/10.1145/2702123.2702322
- Felt et al., Improving SSL Warnings, CHI 2015: https://research.google/pubs/pub43265/
- Petelka, Zou and Schaub, Put Your Warning Where Your Link Is, CHI 2019: https://dl.acm.org/doi/10.1145/3290605.3300748
- Buono et al., Let warnings interrupt the interaction and explain, CHI EA 2023: https://dl.acm.org/doi/10.1145/3544549.3585802
- Reeder et al., An Experience Sampling Study of User Reactions to Browser Warnings, CHI 2018: https://research.google/pubs/an-experience-sampling-study-of-user-reactions-to-browser-warnings-in-the-field/
- Lain, Kostiainen and Čapkun, Phishing in Organizations, IEEE S&P 2022: https://arxiv.org/abs/2112.07498
- NCSC phishing guidance: https://www.ncsc.gov.uk/guidance/phishing
- NCSC, Telling users to avoid clicking bad links still isn't working (2022): https://www.ncsc.gov.uk/blog-post/telling-users-to-avoid-clicking-bad-links-still-isnt-working
- CISA, teach employees to avoid phishing: https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/teach-employees-avoid-phishing

Repository and ObiLabs

- `README.md`, `CLAUDE.md`, `docs/DECISIONS.md`, `docs/RESEARCH.md`, `docs/REPORT-PACKET.md`, `docs/V1-TODO.md`
- `apps-script/Ui.gs`, `Heuristics.gs`, `Report.gs`, `Config.gs`, `Lookups.gs`, `appsscript.json`
- north-star `DECISIONS.md` D-040, D-041, D-042, D-052
