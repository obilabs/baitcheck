# Google developer setup for Obilabs (obilabs.dev)

Goal: everything Baitcheck publishes or calls belongs to Obilabs, not to a
personal account. Do these in order; each depends on the one before.

## 1. Workspace identity
1. Make sure obilabs.dev is a Google Workspace domain with at least one admin
   user (for example admin@obilabs.dev). If Obilabs already has Workspace on
   another domain, add obilabs.dev as a secondary domain in the Admin console
   (Account → Domains) and create the user there instead of a new tenant.
2. Create a shared owner identity rather than a personal one, for example
   dev@obilabs.dev, and make it a Super Admin. Publishing, Cloud project
   ownership and Marketplace listings all hang off this account.
3. Verify the domain in Google Search Console with that account
   (search.google.com/search-console). OAuth verification and the Marketplace
   listing both require a verified domain for the homepage and privacy links.

## 2. Google Cloud
4. Sign in to console.cloud.google.com as dev@obilabs.dev. Because it is a
   Workspace user, an Organization node for obilabs.dev exists automatically.
5. Create a billing account for Obilabs (needed later for Vertex AI and Web
   Risk; nothing is charged until those are used).
6. Create one project named `baitcheck` under the obilabs.dev organization.
   One is enough until there is something in production to protect; a
   second `baitcheck-dev` project (own consent screen, quotas and keys) can
   be added then. Enable APIs: Gmail API, Google Workspace Marketplace SDK,
   Google Workspace Add-ons API, Vertex AI API, Web Risk API.
7. OAuth consent screen (APIs & Services → OAuth consent screen): user type
   **Internal** for now (no verification, own domain only). App name
   "Baitcheck", support email dev@obilabs.dev, homepage and privacy policy on
   obilabs.dev. Switch to **External** only when a public listing is wanted;
   that starts the verification process.
8. Add the scopes the add-on uses (see the add-on manifest). Keep to sensitive
   scopes only.

## 3. Apps Script
9. In script.google.com, sign in as dev@obilabs.dev and link the add-on's
   script project to `baitcheck` (Project Settings → Google Cloud
   Platform project → change project number).
10. Deploy → New deployment → Add-on, for the versioned deployment that the
    Marketplace SDK will reference.

## 4. Marketplace (only when listing publicly or privately to other domains)
11. APIs & Services → Google Workspace Marketplace SDK → App Configuration:
    add-on extensions (Gmail), deployment ID from step 10, visibility Private
    (own domain) or Public.
12. Store Listing: name, descriptions, icons, screenshots, category, links.
13. Publish. Private listings are available immediately to the domain;
    public ones wait for OAuth verification (days for sensitive scopes) and
    Marketplace review.

## 5. Ownership hygiene
- Owner of everything: dev@obilabs.dev, with a second admin as backup.
- Recovery phone and 2-step verification on that account; store credentials
  in the company password manager.
- Never publish from an @gmail.com account: Marketplace publishing is
  disabled for consumer accounts.

Unverified at time of writing: exact current names of the APIs and whether
Internal consent screens are permitted to use restricted scopes without CASA
(they are per Google's docs, but recheck before relying on it).
