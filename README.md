# Baitcheck

Check the bait before you bite. A Gmail add-on that looks at an email **before**
you report it as phishing and tells you, in plain language, what it sees:
a signed newsletter with a working unsubscribe, an internal message, or a
lookalike domain registered last week. Then one click sends the full message
and extracted indicators to your security team, so they get a triaged packet
instead of a bare forward.

Works without AI. Better with it: Gemini through your own Google Cloud project
(no API keys, nothing leaves Google) or a bring-your-own key for Claude or
OpenAI, chosen by the admin.

Free and open source (Apache 2.0), by [Obilabs](https://github.com/obilabs).
A hosted dashboard for security teams is the only part planned as a paid service.

## Status

Research complete, nothing built yet. See `docs/RESEARCH.md` for the platform
constraints, competitor gap, heuristics, and the architecture this will follow:

1. Heuristic verdict card (headers, links, lookalikes, bulk-mail signals), no AI,
   deployed to our own domain first.
2. Report packet: raw `.eml` plus indicators to a security mailbox and Chat.
3. Optional AI second-opinion card via Vertex AI or a customer key.
4. Admin allowlists, user feedback loop, simulation awareness.
5. Dashboard.

## Deployment model

Customer-deployed: the script lives in the customer's own Google Cloud project
as an internal Workspace add-on. No Marketplace review, no CASA assessment,
Vertex AI and Web Risk enabled in the same project, AI costs on the customer's
bill (fractions of a cent per email).

## License

Apache 2.0. See `LICENSE` and `NOTICE`.
