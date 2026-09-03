# Road to Baitcheck 1.0

Open items to settle before a 1.0. Milestone 1 (heuristic card on our own
domain) does not depend on any of these.

## Distribution and accounts
- [ ] Google developer setup under obilabs.dev (see `GOOGLE-DEVELOPER-SETUP.md`)
- [ ] Decide personal-Gmail support: self-install via Test deployments (documented
      guide) now; public Marketplace listing later only if demand justifies
      OAuth verification and, if restricted scopes are ever used, CASA
- [ ] Keep scopes to "sensitive" only (current-message read, send) so a future
      public listing avoids CASA; decide whether delete/label is worth a
      restricted scope (probably not)
- [ ] Standalone AI for individuals: accept an AI Studio Gemini key as well as
      Vertex; state the free-tier data-use difference in the settings card

## Product
- [ ] Report packet schema v1 frozen after milestone 1 real-mail review
- [ ] Connected mode: analyze endpoint contract agreed with the dashboard repo
- [ ] Simulation-header awareness (KnowBe4, Hoxhunt, GoPhish)
- [ ] Web Risk lookup in the customer's project
- [ ] Privacy text for the settings card: what leaves the mailbox in each mode

## Quality
- [ ] Verdicts reviewed on 100+ real emails across newsletters, internal,
      vendor, and known phish samples; false-alarm rate recorded
- [ ] Card renders under 3 s on a large HTML email
- [ ] Unit tests for every heuristic in plain Node
