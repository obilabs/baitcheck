# Status

Updated: 2026-09-16

- Milestone 0 built: copy-paste Apps Script in `apps-script/` (evidence card,
  opt-in "Check links", "Report to security" with .eml + packet). Node tests
  run in CI (`.github/workflows/test.yml`).
- **First real install done.** Installing, `getRawContent`, `GmailApp.sendEmail`
  and card rendering all work. It surfaced three fixes to the report email, now
  made (2026-09-16 decision): the `.eml` is attached as an opaque file so
  receiving clients stop rendering the reported message, the body follows the
  triage order, and it suggests actions with verified Admin console links.
- Still unverified in a real account: the logo URL (served from `main`), and how
  Google Groups renders the new report email.
- Next: manual test on our own domain, review verdicts on real mail, then
  milestone 1 (packaged add-on, see `docs/GOOGLE-DEVELOPER-SETUP.md`).
- Blockers: none. Open questions live in docs/V1-TODO.md.
