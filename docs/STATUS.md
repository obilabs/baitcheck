# Status

Updated: 2026-09-21

- Milestone 0 built: copy-paste Apps Script in `apps-script/` (evidence card,
  opt-in "Check links", "Report to security" with .eml + packet). Node tests
  run in CI (`.github/workflows/test.yml`).
- **First real install done.** Installing, `getRawContent`, `GmailApp.sendEmail`
  and card rendering all work. It surfaced three fixes to the report email, now
  made (2026-09-16 decision): the `.eml` is attached as an opaque file so
  receiving clients stop rendering the reported message, the body follows the
  triage order, and it suggests actions with verified Admin console links.
- **Relayed mail fixed (2026-09-20 decision).** A cold email that reached the
  owner through the `hello@obilabs.dev` Google Group was reported as coming
  from an internal domain, because the group rewrites From and re-signs with
  its own DKIM key. Baitcheck now detects list/group/forwarder delivery, names
  the list, runs the sender checks against `X-Original-Sender`, reports the
  original message's authentication results separately, and says plainly when
  the original sender cannot be determined. Packet schema stays v1 with a new
  `message.relay` object.
- **Company claim from a personal mailbox (2026-09-21 decision).** A cold sales
  email signed "Founder, Anvol" arrived from a free `mail.com` account and was
  only noted as neutral context. It is now a finding, and only when both halves
  are present: a consumer mail provider AND an organisation asserted in the
  display name, with a body link to an outside domain as corroboration. The
  wording gives both readings (sole traders send this way too) and says what
  settles it: ask them to reply from the company domain.
- **Packet publishes the analysis, the headers and the AI prompt (2026-09-21
  decision).** Schema stays v1: new `analysis` (findings with ids and evidence,
  plus the ids of checks that ran clear — absence means not run), new `headers`
  (a filtered set, each as received, absent ones omitted), and `verdict.ai` now
  carries `sent`, the prompt template version and the exact prompt. With AI off
  the prompt travels marked "Not sent", so an admin can read what would leave
  the mailbox before turning AI on. The prompt has one home,
  `apps-script/AiPrompt.gs`; a test asserts the packet's copy is byte-identical.
- **Quick-view card (2026-09-21 decision).** The card now opens with one
  headline (seven fixed ones, in a fixed precedence), one next step, at most
  three short reasons and the Report button; everything else sits in a
  collapsed "Details" section and the note in its own collapsed section. No
  all-clear state: when nothing that can lead the card fired, the headline is
  "Your call: did you expect this?". Along with it: the company-claim check
  also reads the signature block (quoted text cut first); asks for money or a
  sign-in are now their own finding (`payment_or_credential_ask`), separate
  from pressure wording, and both ignore quoted text; a group's
  List-Unsubscribe no longer makes relayed mail read as bulk; relayed mail
  always gets a "came via your group" reason. The packet carries the summary as
  `analysis.summary` (schema still v1).
- **Card styling (2026-09-21 decision).** Each headline has its own Material
  icon (filled for the five caution headlines) and a bold coloured headline:
  warm amber-red for caution, grey for bulk and "your call", no green anywhere.
  Reasons are one icon row each. Report is a filled teal button in the card's
  fixed footer, with Check links as its outlined secondary. The note input has
  one short label. Unverified until a real install: how the icons, the fixed
  colours and the footer look in Gmail's light and dark themes, web and mobile.
- Unverified until a real install: that a `TextInput` inside a collapsed
  section is still submitted with the Report action (the tests only prove the
  wiring), and how the collapsed sections look on mobile.
- Still unverified in a real account: the logo URL (served from `main`), and how
  Google Groups renders the new report email.
- Next: manual test on our own domain, review verdicts on real mail (must
  include one group-relayed and one alias/forwarded message), then
  milestone 1 (packaged add-on, see `docs/GOOGLE-DEVELOPER-SETUP.md`).
- Blockers: none. Open questions live in docs/V1-TODO.md.
