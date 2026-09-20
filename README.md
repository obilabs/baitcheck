# Baitcheck

Check the bait before you bite. Baitcheck is a small Gmail add-on for Google
Workspace. When you open an email, it lists what it notices, such as a sender
name that mentions a brand the address doesn't belong to, replies that would
go to a different domain, or a link whose text doesn't match where it goes.
You decide what to do. If you want to report it, one button sends the original
message to your own security team.

It is not a spam filter and it gives no verdict. The checks are simple and will
miss things. It is meant to help a person take a second look.

Free and open source (Apache 2.0), by [Obilabs](https://github.com/obilabs).

## Status

**Early release: milestone 0, copy-paste Apps Script.** You install it by
pasting a few files into your own Apps Script project. Expect rough edges. It
supersedes PhishLens, an earlier internal prototype that was not published.

## What it checks

All of these run inside Apps Script on the message you opened. None of them
make a network request.

| Check | What you see |
|---|---|
| Brand name vs sending domain | The display name mentions PayPal, Microsoft, DocuSign and so on, but the address isn't on a short list of that brand's domains |
| Reply-To mismatch | Replies would go to a different domain than the sender's |
| Sender authentication | DMARC failed, or SPF failed/softfailed, according to the `Authentication-Results` header. A DKIM pass is shown as context |
| Link text vs destination | A link reads `www.paypal.com` but goes somewhere else |
| URL shorteners, IP addresses | Links that hide where they lead |
| Lookalike domains | `paypa1.com`, `rnicrosoft.com`, `paypal.com.example.net`, or near-copies of your own domains |
| International characters | Punycode (`xn--`) domains that can imitate familiar letters |
| Pressure language | Phrases like "verify your account" or "within 24 hours" |
| Risky attachment types | `.html`, `.svg`, `.iso`, `.lnk`, macro-enabled Office files, and similar |

It also shows neutral context: whether the sender is on your own domain, a
personal mail service, or has a `List-Unsubscribe` header (typical of
newsletters).

## What leaves your mailbox

- **When you open a message: nothing.** The checks run locally in Apps Script.
  The automated tests fail if any network call is added to this path.
- **When you press "Check links":** only the link addresses from that message
  (up to 20) go to the lookup services your admin turned on. Nothing else is
  sent: no subject, body, sender or attachments. The button only appears when
  at least one service is configured. Results are cached in your own user cache
  for an hour.
- **When you press "Report to security":** your mailbox sends one email to the
  `REPORT_ADDRESS` your admin set. It contains the original message as
  `reported-message.eml` (full headers), a `baitcheck-report.json` summary
  (see [`docs/REPORT-PACKET.md`](docs/REPORT-PACKET.md)), and your optional note.
  The reported message stays in your mailbox. Baitcheck never moves, labels or
  deletes mail.

### What the security team receives

One plain-text email, laid out in the order someone triages it:

1. **What happened** — that the reporter is the sender of the report, when they
   reported it, the subject, and their note.
2. **What Baitcheck noticed** — the signals from the checks above. No verdict.
3. **The facts** — display name and address separately, Reply-To, Return-Path,
   SPF/DKIM/DMARC, the link domains (deduplicated, with a count), and the
   attachment names with their sha256.
4. **Suggested actions** — block the sender address, block the sending domain,
   find out who else received it, or do nothing; each with the reason and a
   link to the right Google Admin console page. They are suggestions for a
   human. Baitcheck cannot carry any of them out: that would need
   `gmail.modify` or admin scopes it deliberately does not request.
5. **What is attached** — `reported-message.zip` (containing
   `reported-message.eml`) and `baitcheck-report.json`, plus the report ID. The
   original is zipped because mail clients and Google Groups render an attached
   email inline, which would load its remote images and tracking pixels from the
   security team's network and put a live link in front of the reader. Declaring
   a different MIME type is not enough: Gmail's send API re-types an attached
   `.eml` by sniffing its contents (seen live, 2026-09-20). Nothing renders the
   inside of a zip.
6. **What Baitcheck did not do** — it did not move, delete or quarantine the
   message, and the reporter still has it.

Obilabs receives nothing. There is no Obilabs server in milestone 0.

## Install

You need a Google Workspace account where add-ons from Apps Script are allowed.
This works for a single user trying it on their own mailbox. An admin can use
the same steps to test before rolling it out.

1. Go to [script.google.com](https://script.google.com) and create a **New project**.
   Name it `Baitcheck`.
2. **Project Settings** (gear icon): tick **Show "appsscript.json" manifest file
   in editor**.
3. In the editor, replace the contents of `appsscript.json` with
   [`apps-script/appsscript.json`](apps-script/appsscript.json).
4. Delete the default `Code.gs`. Add one script file per file in
   [`apps-script/`](apps-script/) and paste its contents: `Config`, `Heuristics`,
   `Lookups`, `Report`, `Ui` (the editor adds `.gs`).
5. **Project Settings -> Script properties**: add the properties you want
   (see below). With none set, the checks work and the Report and Check links
   buttons stay hidden.
6. Click **Deploy -> Test deployments**, then **Install**. The first time you
   open the add-on in Gmail, Google asks you to authorize the scopes listed below.
7. Open Gmail (reload it), open any email, and click the Baitcheck icon in the
   right-hand side panel.

To roll it out to a whole domain, the Apps Script project needs to be linked to
a Google Cloud project and deployed through the Google Workspace Marketplace
SDK as a private (internal) app. That path is documented in
[`docs/GOOGLE-DEVELOPER-SETUP.md`](docs/GOOGLE-DEVELOPER-SETUP.md) and is what
milestone 1 will package properly.

If you use [`clasp`](https://github.com/google/clasp), `clasp push` from the
`apps-script/` directory works too (`.claspignore` keeps the tests out). Keep `.clasp.json` out of git.

## Configuration

All settings are Script Properties. Keys are secrets: they sit in the script
project, not in this repository, and anyone with edit access to the script can
read them.

| Property | Example | Effect |
|---|---|---|
| `REPORT_ADDRESS` | `security@example.com` | Where reports go. Empty: no Report button |
| `ORG_DOMAINS` | `example.com,example.co.uk` | Your domains, for "internal sender" and lookalike checks |
| `LOOKUP_SERVICES` | `urlhaus,webrisk` | Lookups offered behind "Check links". Empty: no lookups and no external requests |
| `URLHAUS_AUTH_KEY` | | Free key from [auth.abuse.ch](https://auth.abuse.ch/). Required for `urlhaus` |
| `WEBRISK_API_KEY` | | API key from your own Google Cloud project with the Web Risk API enabled. Required for `webrisk` |
| `SAFEBROWSING_API_KEY` | | API key for Google Safe Browsing. Required for `safebrowsing` |
| `VIRUSTOTAL_API_KEY` | | VirusTotal key. Required for `virustotal` |

A service is used only when it is listed in `LOOKUP_SERVICES` **and** its key
is set. Check each service's terms for your situation: Google Safe Browsing's
free API is for non-commercial use (Web Risk is Google's commercial
equivalent), and VirusTotal's public API is not for commercial products.

## Scopes

| Scope | Why |
|---|---|
| `gmail.addons.execute` | Required for any Gmail add-on to run |
| `gmail.addons.current.message.readonly` | Read the message you have open (headers, body, attachment names, raw content for the report). Only that message, only while it is open |
| `gmail.send` | Send the report email from your mailbox to `REPORT_ADDRESS`. It cannot read your mail |
| `script.external_request` | Make the "Check links" lookups. Only used when you press the button and a service is configured. Requests are limited to the hosts in the manifest's `urlFetchWhitelist` |

Not requested: full Gmail access (`https://mail.google.com/`), `gmail.modify`
or `gmail.readonly`. Moving a reported message to trash would need
`gmail.modify`, a restricted scope, so Baitcheck does not offer it. If you
never plan to enable lookups, you can remove `script.external_request` from
the manifest; leave `LOOKUP_SERVICES` empty in that case.

## Development

The checks are plain JavaScript with no Google services, so they are tested in
Node without a Google account. The harness loads the `.gs` files into a
sandbox with stubbed Gmail, CardService and UrlFetchApp objects.

```sh
node --test "apps-script/test/*.test.js"
```

Node 22 or newer. No dependencies to install.

## Roadmap

No dates. In rough order:

1. **Milestone 1:** a packaged Google Workspace add-on an admin can install for
   their domain through the Google Workspace Marketplace, instead of pasting files.
2. More checks from [`docs/RESEARCH.md`](docs/RESEARCH.md): domain age,
   simulation-email awareness, admin allowlists.
3. An optional AI second opinion, off by default, running in your own Google
   Cloud project.
4. A dashboard for security teams that receives report packets. This is the
   only part planned as a paid service; the add-on stays free.

See [`docs/DECISIONS.md`](docs/DECISIONS.md) for the reasoning behind these.

## Security

See [`SECURITY.md`](SECURITY.md) to report a vulnerability.

## License

Apache 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Built with AI-assisted development (Claude Code), under human direction and review.
