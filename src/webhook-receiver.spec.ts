import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createIdempotencyStore } from '@nexus/webhooks';
import { PartnerState } from './state.js';
import { partnerWebhookHandlers, receiveNexusWebhook } from './webhook-receiver.js';

const secret = 'whsec_test';

function signed(body: string) {
  const t = Math.floor(Date.now() / 1000);
  const v1 = createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');
  return { body, header: `t=${t},v1=${v1}` };
}

describe('receiveNexusWebhook', () => {
  it('rejects a bad signature and dedupes event ids', async () => {
    const state = new PartnerState();
    const handlers = partnerWebhookHandlers(state, { info() {}, warn() {} });
    const payload = signed(JSON.stringify({
      eventId: 'e1',
      event: 'grant.revoked',
      eventVersion: 1,
      clientId: 'client-1',
      at: '2026-10-02T12:00:00.000Z',
      data: { grantId: 'g1', clientId: 'client-1', sub: 'pairwise', reason: 'user' },
    }));
    const bad = await receiveNexusWebhook({
      rawBody: payload.body,
      headers: { 'x-nexus-signature': 't=1,v1=00' },
      secret,
      handlers,
    });
    expect(bad.status).toBe(401);

    const store = createIdempotencyStore();
    const ok = await receiveNexusWebhook({
      rawBody: payload.body,
      headers: { 'x-nexus-signature': payload.header },
      secret,
      handlers,
      idempotency: store,
    });
    const again = await receiveNexusWebhook({
      rawBody: payload.body,
      headers: { 'x-nexus-signature': payload.header },
      secret,
      handlers,
      idempotency: store,
    });
    expect(ok.body).toEqual({ ok: true });
    expect(again.body).toEqual({ ok: true, duplicate: true });
    expect(state.grants.get('g1')?.revoked).toBe(true);
  });

  it('does not mark an event as seen when the handler fails, so the retry is processed', async () => {
    const store = createIdempotencyStore();
    let calls = 0;
    const handlers = {
      'grant.revoked': () => {
        calls += 1;
        if (calls === 1) throw new Error('db down');
      },
    };
    const payload = signed(JSON.stringify({
      eventId: 'e-retry',
      event: 'grant.revoked',
      eventVersion: 1,
      clientId: 'client-1',
      at: '2026-10-02T12:00:00.000Z',
      data: { grantId: 'g1', clientId: 'client-1', sub: 'pairwise', reason: 'user_revoked' },
    }));
    const req = { rawBody: payload.body, headers: { 'x-nexus-signature': payload.header }, secret, handlers, idempotency: store };
    expect((await receiveNexusWebhook(req)).status).toBe(500);
    expect((await receiveNexusWebhook(req)).body).toEqual({ ok: true });
    expect(calls).toBe(2);
  });

  it('hands a privacy request to the kit once', async () => {
    const seen: string[] = [];
    const state = new PartnerState();
    const handlers = partnerWebhookHandlers(state, { info() {}, warn() {} }, {
      async handleEvent(envelope) {
        seen.push(envelope.eventId);
      },
    });
    const payload = signed(JSON.stringify({
      eventId: 'e-privacy',
      event: 'privacy_request.created',
      eventVersion: 1,
      clientId: 'client-1',
      at: '2026-10-05T12:00:00.000Z',
      data: { requestId: 'req-1', type: 'access', sub: 'pairwise', grantId: 'g1', dueAt: '2026-11-05T12:00:00.000Z' },
    }));
    const store = createIdempotencyStore();
    const req = { rawBody: payload.body, headers: { 'x-nexus-signature': payload.header }, secret, handlers, idempotency: store };
    expect((await receiveNexusWebhook(req)).status).toBe(200);
    expect((await receiveNexusWebhook(req)).body).toEqual({ ok: true, duplicate: true });
    expect(seen).toEqual(['e-privacy']);
  });

  it('drops mirrored grants on account.erased', async () => {
    const state = new PartnerState();
    state.setFields('g1', 'pairwise-a', ['email']);
    state.setFields('g2', 'pairwise-b', []);
    state.setFields('g3', 'pairwise-other', []);
    const handlers = partnerWebhookHandlers(state, { info() {}, warn() {} });
    const erased = signed(JSON.stringify({
      eventId: 'e-erased',
      event: 'account.erased',
      eventVersion: 1,
      clientId: 'client-1',
      at: '2026-10-02T12:00:00.000Z',
      data: { clientId: 'client-1', grantIds: ['g1'], subs: ['pairwise-a', 'pairwise-b'], reason: 'user_erasure' },
    }));
    const res = await receiveNexusWebhook({
      rawBody: erased.body,
      headers: { 'x-nexus-signature': erased.header },
      secret,
      handlers,
    });
    expect(res.status).toBe(200);
    expect([...state.grants.keys()]).toEqual(['g3']);
  });

  it('caches regulatory status and granted fields', async () => {
    const state = new PartnerState();
    state.setFields('g1', 'pairwise', []);
    const handlers = partnerWebhookHandlers(state, { info() {}, warn() {} });
    const regulatory = signed(JSON.stringify({
      eventId: 'e-reg',
      event: 'regulatory.status_changed',
      eventVersion: 1,
      clientId: 'client-1',
      at: '2026-10-02T12:00:00.000Z',
      data: {
        grantId: 'g1',
        clientId: 'client-1',
        sub: 'pairwise',
        subjectType: 'org_member',
        bundleSlug: 'identification-l1',
        target: 'user',
        status: 'verified',
        previousStatus: 'none',
      },
    }));
    await receiveNexusWebhook({
      rawBody: regulatory.body,
      headers: { 'x-nexus-signature': regulatory.header },
      secret,
      handlers,
    });
    expect(state.grants.get('g1')?.regulatoryStatus).toBe('verified');

    const fields = signed(JSON.stringify({
      eventId: 'e-fields',
      event: 'grant.fields_changed',
      eventVersion: 1,
      clientId: 'client-1',
      at: '2026-10-02T12:00:00.000Z',
      data: { grantId: 'g1', clientId: 'client-1', sub: 'pairwise', grantedFields: ['email'] },
    }));
    await receiveNexusWebhook({
      rawBody: fields.body,
      headers: { 'x-nexus-signature': fields.header },
      secret,
      handlers,
    });
    expect(state.grants.get('g1')?.grantedFields).toEqual(['email']);
  });
});
