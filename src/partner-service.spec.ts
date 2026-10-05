import { createSign, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createTestClient, fixtureOk } from '@nexus/commands-client/testing';
import { ElevationRequiredError } from '@nexus/commands-client';
import { mapPartnerError, PartnerService } from './partner-service.js';
import { PartnerState } from './state.js';

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

describe('PartnerService', () => {
  const issuer = 'https://region.example';
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  jwk.kid = 'kid-1';
  const now = Math.floor(Date.now() / 1000);
  const attestation = (() => {
    const header = b64url(Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'kid-1' })));
    const payload = b64url(Buffer.from(JSON.stringify({
      iss: issuer,
      aud: 'client-1',
      sub: 'pairwise-org',
      typ: 'anx-regulatory-status',
      grantId: 'g-org',
      subjectType: 'org_member',
      statuses: [{ bundleSlug: 'kyb-l1', kind: 'kyb', target: 'org', status: 'verified' }],
      iat: now,
      exp: now + 300,
    })));
    const data = `${header}.${payload}`;
    const sig = createSign('RSA-SHA256').update(data).end().sign(privateKey);
    return `${data}.${b64url(sig)}`;
  })();

  function service() {
    const state = new PartnerState();
    const client = createTestClient({
      'anx.oauth2.subject.identities.list': () => fixtureOk({
        identities: [{
          subjectType: 'org_member',
          sub: 'pairwise-org',
          grantId: 'g-org',
          organization: { orgId: 'org-1', name: 'Acme', logoUrl: 'https://cdn.example/logo.png' },
        }],
      }),
      'anx.oauth2.subject.regulatory-status.get': () => fixtureOk({
        statuses: [{ bundleSlug: 'kyb-l1', kind: 'kyb', target: 'org', status: 'verified' }],
        attestation,
        attestationExpiresAt: '2026-10-02T12:05:00.000Z',
      }),
      'anx.oauth2.subject.fields.get': () => fixtureOk({ fields: { email: 'a@b.c' }, omitted: [] }),
      'anx.oauth2.subject.fields.request': () => fixtureOk({
        requestId: 'fr-1',
        alreadyGranted: [],
        pending: ['phone'],
      }),
      'anx.permission-grants.requests.create': () => fixtureOk({
        requestId: 'req-1',
        approvalUrl: '/oauth/permission-requests/req-1',
        created: true,
        status: 'open',
        items: [],
      }),
      'anx.oauth2.app-subscription.get': () => fixtureOk({
        tiers: [{ tierId: 'free', name: 'Free', isDefault: true, price: 0 }],
        activeTier: [{ tierId: 'free' }],
        managedExternally: false,
      }),
      'anx.compliance.security-policy.get': () => fixtureOk({
        orgId: 'org-1',
        enabled: true,
        requirePersonalPassword: true,
        membershipLoginPassword: 'membership_password',
        minTwoFactorFactors: 2,
        enforcementMode: 'warn',
        requireBiometric: false,
      }),
      'anx.compliance.org-overview.get': () => fixtureOk({
        orgId: 'org-1',
        securityPolicyEnabled: true,
        activations: [],
        regulatoryBundles: [{ slug: 'identification-l1', status: 'VERIFIED' }],
        requiredGaps: [],
        suggestions: [],
      }),
    });
    const svc = new PartnerService({
      issuer,
      portalOrigin: 'https://portal.example',
      clientId: 'client-1',
      redirectUri: 'http://127.0.0.1:8787/callback',
      jwks: { getKey: async (kid) => (kid === 'kid-1' ? jwk : null) },
      state,
      logger: { info() {}, warn() {} },
      clientForToken: () => client,
      exchange: async () => ({
        access_token: 'access-token',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'refresh-token',
        subject_type: 'org_member',
        org_id: 'org-1',
      }),
    });
    return { svc, state, client };
  }

  it('starts an org-member authorize and completes it without returning tokens', async () => {
    const { svc, state } = service();
    const started = await svc.startLogin({ subjectType: 'org_member', orgId: 'org-1' });
    const url = new URL(started.authorizeUrl);
    expect(url.searchParams.get('subject_type')).toBe('org_member');
    expect(url.searchParams.get('org_id')).toBe('org-1');
    const intent = state.session(started.sessionId)?.intent;
    await svc.completeLogin({
      sessionId: started.sessionId,
      code: 'code-1',
      state: intent?.state || '',
    });
    const session = state.session(started.sessionId);
    expect(session?.accessToken).toBe('access-token');
    expect(session?.intent).toBeUndefined();
    expect(session?.subjectType).toBe('org_member');
  });

  it('lists identities, verifies status, requests a field, and returns a batch approval url', async () => {
    const { svc, state, client } = service();
    const started = await svc.startLogin({ subjectType: 'org_member', orgId: 'org-1' });
    const intent = state.session(started.sessionId)?.intent;
    await svc.completeLogin({ sessionId: started.sessionId, code: 'c', state: intent?.state || '' });

    const identities = await svc.identities(started.sessionId);
    expect(identities.identities[0]?.organization?.name).toBe('Acme');
    const status = await svc.status(started.sessionId);
    expect(status.statuses[0]?.kind).toBe('kyb');
    expect(status).not.toHaveProperty('attestation');
    const fields = await svc.requestFields(started.sessionId, [{ field: 'phone', purpose: 'recovery' }]);
    expect(fields.pending).toEqual(['phone']);
    await expect(svc.requestFields(started.sessionId, [{ field: 'passport' }])).rejects.toMatchObject({
      code: 'FIELD_CONSENT_INVALID',
    });
    const batch = await svc.requestBatch(started.sessionId, [
      { kind: 'command', commandName: 'anx.crm.project.list' },
    ]);
    expect(batch.approvalUrl).toBe('https://portal.example/oauth/permission-requests/req-1');
    const subscription = await svc.subscription(started.sessionId);
    expect(subscription.activeTier).toEqual([{ tierId: 'free' }]);
    expect(subscription.managedExternally).toBe(false);
    const compliance = await svc.orgCompliance(client);
    expect(compliance.policy.membershipLoginPassword).toBe('membership_password');
    expect(compliance.policy.requirePersonalPassword).toBe(true);
    expect(compliance.overview.regulatoryBundles[0]?.slug).toBe('identification-l1');
  });

  it('mints a new server session id and does not reuse a planted one', async () => {
    const { svc, state } = service();
    state.saveSession({ id: 'client-supplied' });
    const first = await svc.startLogin({ subjectType: 'user' });
    const second = await svc.startLogin({ subjectType: 'org_member', orgId: 'org-1' });
    expect(first.sessionId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    expect(second.sessionId).not.toBe(first.sessionId);
    expect(first.sessionId).not.toBe('client-supplied');
    expect(state.session('client-supplied')?.intent).toBeUndefined();
    expect(state.session(second.sessionId)?.intent?.orgId).toBe('org-1');
  });

  it('maps elevation to 409 with a portal approval url', () => {
    const err = new ElevationRequiredError({
      approvalUrl: '/oauth/permission-requests/req-9',
      elevationRequestId: 'req-9',
    });
    expect(mapPartnerError(err, 'https://portal.example')).toEqual({
      status: 409,
      body: {
        error: 'PERMISSION_ELEVATION_REQUIRED',
        approvalUrl: 'https://portal.example/oauth/permission-requests/req-9',
        elevationRequestId: 'req-9',
      },
    });
  });

  it('rejects a non-http elevation approval url', () => {
    const err = new ElevationRequiredError({
      approvalUrl: 'javascript:alert(1)',
      elevationRequestId: 'req-9',
    });
    expect(mapPartnerError(err, 'https://portal.example')).toMatchObject({
      status: 400,
      body: { error: 'VALIDATION' },
    });
  });
});
