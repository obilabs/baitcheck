# Status

Updated: 2026-09-13

- Milestone 0 built: copy-paste Apps Script in `apps-script/` (evidence card,
  opt-in "Check links", "Report to security" with .eml + packet). Node tests
  run in CI (`.github/workflows/test.yml`).
- Not yet verified in a real Gmail account: install via Test deployments,
  `getRawContent` under the current-message scope, `GmailApp.sendEmail` under
  `gmail.send`, card rendering, and the logo URL (served from `main`).
- Next: manual test on our own domain, review verdicts on real mail, then
  milestone 1 (packaged add-on, see `docs/GOOGLE-DEVELOPER-SETUP.md`).
- Blockers: none. Open questions live in docs/V1-TODO.md.
