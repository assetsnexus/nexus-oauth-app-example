# Login with Nexus partner example

Node BFF that signs a user in with Login with Nexus and then calls the region with `@nexus/commands-client`. The browser never sees the access token. This is the same package the portal and xcamp use. Do not copy the OAuth helpers into the example.

Docs entry: [Login with Nexus](../../anx-docs/content/developers/integrate/02-login-with-nexus.md).

| Call | Client |
|------|--------|
| Authorize URL and PKCE | `buildAuthorizeUrl`, `generatePkce` |
| Code exchange | `exchangeAuthorizationCode` (`REQUIREMENTS_NOT_MET` stays on `NexusError`) |
| Consented identities | `client.subject.identities()` |
| Bundle status | `client.subject.regulatoryStatus()` then `verifyAttestation` |
| Field claims | `client.subject.fields.get` / `.request` |
| Permission batch | `client.permissions.requestBatch` |
| App subscription | `client.subscriptions.getActiveTier()` — the region returns only the free tier |
| Org password and compliance | `client.orgAdmin.securityPolicy()` and `.complianceOverview()` — org session or API key, not the app access token |

Deep dives:

- [Login requirements](../../anx-docs/content/developers/integrate/10-login-requirements.md) — `loginRequirements.minVerificationLevel`, `requiredBundles`, bundle `identification-l1`
- [Org security policy](../../anx-docs/content/developers/integrate/11-org-security-policy.md) — `requirePersonalPassword`, `membershipLoginPassword`
- [Regulatory status and fields](../../anx-docs/content/developers/integrate/12-regulatory-status-and-fields.md)
- [Partner webhooks](../../anx-docs/content/developers/integrate/05-partner-webhooks.md)
- [App Gallery](../../anx-docs/content/developers/app-store/01-subscriptions.md) — paid app plans are not implemented

## Setup

Build the SDK packages first, then install and start:

```bash
npm run build --prefix ../../anx-npm-modules/packages/commands-client
npm run build --prefix ../../anx-npm-modules/packages/webhooks
npm install
```

```bash
NEXUS_ISSUER=https://region.example \
NEXUS_PORTAL_ORIGIN=https://portal.example \
NEXUS_CLIENT_ID=client \
NEXUS_CLIENT_SECRET=secret \
NEXUS_REDIRECT_URI=http://127.0.0.1:8787/callback \
NEXUS_WEBHOOK_SECRET=whsec \
npm start
```

Open http://127.0.0.1:8787. Point the Nexus app webhook at `http://127.0.0.1:8787/api/webhooks/nexus`.

`NEXUS_PORTAL_ORIGIN` is the portal the user approves on. Region approval links are paths (`/oauth/permission-requests/<id>`); the BFF turns them into `http:` or `https:` URLs on that origin before the browser opens them. The session cookie is `HttpOnly` and is `Secure` when the request host is not localhost.

`npm test` runs the BFF unit tests against the SDK source.
