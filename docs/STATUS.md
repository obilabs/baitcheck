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
- Still unverified in a real account: the logo URL (served from `main`), and how
  Google Groups renders the new report email.
- Next: manual test on our own domain, review verdicts on real mail (must
  include one group-relayed and one alias/forwarded message), then
  milestone 1 (packaged add-on, see `docs/GOOGLE-DEVELOPER-SETUP.md`).
- Blockers: none. Open questions live in docs/V1-TODO.md.
